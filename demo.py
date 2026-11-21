"""ACG demo: Alice and Bob chat with AES-256 while the Interceptor listens in.

Opening this starts all three windows. Alice chooses how the AES key is locked:
RSA (a tiny key Shor's can crack) or PQC (ML-KEM-768, which Shor's can't).
"""
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import common

PORT = 47100
BG, PANEL, FG, RED, TEAL = '#111418', '#1b2027', '#e8eaed', '#ff6b4a', '#2dd4bf'


class Person:
    """Alice's or Bob's chat window."""

    def __init__(self, demo, name, x, width):
        self.demo, self.name, self.conn, self.key = demo, name, None, None
        self.win = demo.window(name, x, width)
        self.top = tk.Frame(self.win)
        self.top.pack(fill='x', padx=10, pady=8)
        self.status = tk.Label(self.top, text='Not connected', anchor='w')
        self.status.pack(side='left')
        self.log = tk.Text(self.win, relief='flat', bg=PANEL, state='disabled', padx=8, highlightthickness=0)
        self.log.pack(fill='both', expand=True, padx=10)
        self.box = tk.Entry(self.win, relief='flat', bg=PANEL)
        self.box.pack(fill='x', padx=10, pady=10, ipady=6)
        self.box.bind('<Return>', self.send)

    def say(self, line):
        self.log.config(state='normal')
        self.log.insert('end', line + '\n')
        self.log.config(state='disabled')
        self.log.see('end')

    def connected(self, conn, lines, key, lock):
        if self.conn:
            self.conn.close()                            # switching lock: end the old chat
        self.conn, self.key = conn, key
        self.status.config(text=f'AES key locked with {lock}', fg=RED if lock.startswith('RSA') else TEAL)
        self.say(f'--- new chat, AES key locked with {lock} ---')
        threading.Thread(target=self.listen, args=(conn, lines), daemon=True).start()

    def listen(self, conn, lines):
        other = 'Bob' if self.name == 'Alice' else 'Alice'
        try:
            for line in lines:
                text = common.decrypt(self.key, json.loads(line)['msg'])
                self.demo.later(lambda text=text: self.say(f'{other}: {text}'))
        except (OSError, ValueError):
            pass

    def send(self, _):
        if self.conn and self.box.get():
            common.send(self.conn, {'msg': common.encrypt(self.key, self.box.get())})
            self.say(f'You: {self.box.get()}')
            self.box.delete(0, 'end')


class Interceptor:
    """Sniffs the Alice-Bob traffic (Npcap loopback) and attacks each session."""

    def __init__(self, demo, x, width):
        self.demo, self.sessions, self.buffers = demo, {}, {}
        win = demo.window('Interceptor', x, width)
        self.tabs = ttk.Notebook(win)
        self.tabs.pack(fill='both', expand=True, padx=6, pady=6)
        from scapy.all import AsyncSniffer
        self.sniffer = AsyncSniffer(iface=r'\Device\NPF_Loopback', prn=self.packet, store=False,
                                    filter=f'tcp port {PORT}')
        self.sniffer.start()

    def packet(self, pkt):
        """Sniffer thread: rebuild the JSON lines from TCP payloads."""
        tcp = pkt['TCP']
        from_alice = tcp.dport == PORT
        conn = tcp.sport if from_alice else tcp.dport
        payload = bytes(tcp.payload)[:pkt['IP'].len - pkt['IP'].ihl * 4 - tcp.dataofs * 4]
        if payload:
            *done, self.buffers[conn, from_alice] = (self.buffers.get((conn, from_alice), b'') + payload).split(b'\n')
            for line in done:
                try:
                    data = json.loads(line)
                except ValueError:
                    continue
                self.demo.later(lambda data=data: self.seen(conn, from_alice, data))

    def seen(self, conn, from_alice, data):
        session = self.sessions.setdefault(conn, {'messages': []})
        if not from_alice and 'lock' in data:            # Bob's public key
            session['public'] = data
        elif ('locked' in data or 'ciphertext' in data) and 'public' in session:   # Alice's locked AES key
            session['start'] = data
            self.new_tab(session)
        elif 'msg' in data and 'tab' in session:
            session['messages'].append(('Alice' if from_alice else 'Bob', data['msg']))
            self.draw(session)

    def new_tab(self, s):
        public = s['public']
        rsa = public['lock'] == 'RSA'
        s['tab'] = tab = tk.Frame(self.tabs)
        self.tabs.add(tab, text=f'Chat {len(self.tabs.tabs()) + 1} · {"RSA" if rsa else "PQC"}')
        lock = f'RSA  N = {public["N"]}, e = {public["e"]}' if rsa else 'ML-KEM-768'
        tk.Label(tab, text=f'Captured: AES key locked with {lock}').pack(anchor='w', padx=8, pady=(6, 0))
        s['status'] = tk.Label(tab, text='', fg='#8a939c')
        s['status'].pack(anchor='w', padx=8, pady=(0, 6))
        s['result'] = tk.Label(tab, text='', justify='left', font='Consolas 10')
        s['result'].pack(side='bottom', anchor='w', padx=8, pady=(0, 8))
        s['button'] = tk.Button(tab, text="Crack with Shor's", bg=RED, fg='black', relief='flat',
                                command=lambda: self.crack(s))
        s['button'].pack(side='bottom', anchor='w', padx=8, pady=8)
        s['text'] = tk.Text(tab, relief='flat', bg=PANEL, font='Consolas 10', padx=8, highlightthickness=0)
        s['text'].pack(fill='both', expand=True, padx=8)
        self.tabs.select(tab)
        self.draw(s)

    def draw(self, s):
        """Hold encrypted messages until the key is cracked, then decrypt them all and every new one live."""
        if 'key' in s:
            s['status'].config(text='● LIVE: key cracked, decrypting messages as they arrive', fg=RED)
        else:
            s['status'].config(text=f'Holding {len(s["messages"])} encrypted message(s) until the key is cracked')
        s['text'].delete('1.0', 'end')
        for who, blob in s['messages']:
            s['text'].insert('end', f'{who:>5}  ' + (common.decrypt(s['key'], blob) if 'key' in s else blob[:44] + '…') + '\n')
        s['text'].see('end')

    def crack(self, s):
        s['button'].config(state='disabled', bg=PANEL)
        if s['public']['lock'] != 'RSA':
            return s['result'].config(fg=TEAL, text="Can't crack it: ML-KEM has no\nhidden period for Shor's to find.")
        s['result'].config(text="Running Shor's…")
        threading.Thread(target=self.shor, args=(s,), daemon=True).start()

    def shor(self, s):
        """Runs shor.py as its own process so the windows never freeze."""
        n, e = s['public']['N'], s['public']['e']
        found = json.loads(subprocess.run([sys.executable, 'shor.py', str(n)], capture_output=True, text=True,
                                          cwd=os.path.dirname(os.path.abspath(__file__)),
                                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout)
        p, q = found['factors']
        d = pow(e, -1, (p - 1) * (q - 1))
        key = common.rsa_unlock(s['start']['locked'], n, d)
        self.demo.later(lambda: (s.update(key=key), self.draw(s), s['result'].config(fg=RED, text=(
            f'Period r = {found["r"]}  →  N = {n} = {p} × {q}\n'
            f'Private key d = {d}  →  AES key recovered in {found["seconds"]:.1f} s'))))


class Demo:
    def __init__(self):
        self.server = socket.socket()
        try:
            self.server.bind(('127.0.0.1', PORT))
        except OSError:
            messagebox.showinfo('ACG demo', 'The demo is already open.')
            sys.exit()
        self.server.listen()
        self.root, self.todo = tk.Tk(), queue.Queue()
        self.root.withdraw()
        for option, value in (('*Background', BG), ('*Foreground', FG), ('*Font', 'Segoe 11'),
                              ('*insertBackground', FG)):
            self.root.option_add(option, value)
        width = self.root.winfo_screenwidth() // 3 - 16
        self.alice = Person(self, 'Alice', 8, width)
        self.bob = Person(self, 'Bob', width + 24, width)
        self.interceptor = Interceptor(self, 2 * width + 40, width)
        for lock, color in (('PQC', TEAL), ('RSA', RED)):     # packed right-to-left: RSA shows first
            tk.Button(self.alice.top, text=lock, bg=color, fg='black', relief='flat', width=6,
                      command=lambda lock=lock: self.connect(lock)).pack(side='right', padx=2)
        threading.Thread(target=self.bob_accepts, daemon=True).start()
        self.root.after(1500, lambda: self.connect('RSA'))   # give the sniffer a moment to start
        self.tick()

    def window(self, title, x, width):
        win = tk.Toplevel(self.root, bg=BG)
        win.title(title)
        win.geometry(f'{width}x520+{x}+40')
        win.protocol('WM_DELETE_WINDOW', self.quit)
        return win

    def later(self, job):
        """Background threads hand UI work to the main thread."""
        self.todo.put(job)

    def tick(self):
        while not self.todo.empty():
            self.todo.get()()
        self.root.after(100, self.tick)

    def connect(self, lock):
        """Alice opens a new chat with Bob using the chosen lock."""
        def run():
            conn = socket.create_connection(('127.0.0.1', PORT))
            lines = conn.makefile('r')
            common.send(conn, {'lock': lock})
            public = json.loads(lines.readline())
            if lock == 'RSA':
                key = os.urandom(32)
                common.send(conn, {'locked': common.rsa_lock(key, public['N'], public['e'])})
                label = f'RSA (N = {public["N"]})'
            else:
                key, ciphertext = common.pqc_lock(public['public'])
                common.send(conn, {'ciphertext': ciphertext})
                label = 'ML-KEM-768'
            self.later(lambda: self.alice.connected(conn, lines, key, label))
        threading.Thread(target=run, daemon=True).start()

    def bob_accepts(self):
        """Bob makes a fresh key pair for every chat and unlocks the AES key Alice sends."""
        while True:
            conn, _ = self.server.accept()
            lines = conn.makefile('r')
            lock = json.loads(lines.readline())['lock']
            if lock == 'RSA':
                n, e, d = common.rsa_keys()
                common.send(conn, {'lock': 'RSA', 'N': n, 'e': e})
                key = common.rsa_unlock(json.loads(lines.readline())['locked'], n, d)
                label = f'RSA (N = {n})'
            else:
                private = common.pqc_keys()
                common.send(conn, {'lock': 'PQC', 'public': common.pqc_public(private)})
                key = common.pqc_unlock(private, json.loads(lines.readline())['ciphertext'])
                label = 'ML-KEM-768'
            self.later(lambda conn=conn, lines=lines, key=key, label=label: self.bob.connected(conn, lines, key, label))

    def quit(self):
        self.interceptor.sniffer.stop()
        self.root.destroy()


if __name__ == '__main__':
    Demo().root.mainloop()
