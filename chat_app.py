"""ACG Chat. Open as many windows as you like; they find each other."""
import queue
import threading
import tkinter as tk

import network
from protocol import ProtocolError

BG, PANEL, TEXT, MUTED = '#111418', '#1b2027', '#e8eaed', '#8a939c'
COLOR = {'rsa': '#ff6b4a', 'pqc': '#2dd4bf'}
LOCK = {'rsa': 'RSA', 'pqc': 'Post-quantum'}
FONT = ('Segoe UI', 11)


class ChatApp:
    def __init__(self, root):
        self.root, self.events = root, queue.Queue()
        self.me = self.node = self.current = None
        self.chats, self.logs, self.peers = {}, {}, []
        root.title('ACG Chat')
        root.configure(bg=BG)
        root.geometry('760x500')
        root.protocol('WM_DELETE_WINDOW', self.quit)
        self.start_screen()
        root.after(100, self.pump)

    def label(self, parent, text, **kw):
        return tk.Label(parent, text=text, bg=kw.pop('bg', BG), fg=kw.pop('fg', TEXT), font=kw.pop('font', FONT), **kw)

    # ----- start screen -----
    def start_screen(self):
        self.start = tk.Frame(self.root, bg=BG)
        self.start.place(relx=0.5, rely=0.45, anchor='center')
        self.label(self.start, 'Your name').pack(anchor='w')
        self.name = tk.Entry(self.start, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief='flat', font=('Segoe UI', 13), width=24)
        self.name.pack(fill='x', ipady=6, pady=(4, 16))
        self.name.focus_set()
        row = tk.Frame(self.start, bg=BG)
        row.pack(fill='x')
        for mode in ('rsa', 'pqc'):
            tk.Button(row, text=LOCK[mode], command=lambda m=mode: self.begin(m), bg=COLOR[mode], fg='#000',
                      relief='flat', font=('Segoe UI Semibold', 11), padx=16, pady=6, bd=0, cursor='hand2'
                      ).pack(side='left', expand=True, fill='x', padx=(0, 6) if mode == 'rsa' else 0)
        self.error = self.label(self.start, '', fg=COLOR['rsa'])
        self.error.pack(pady=(10, 0))

    def begin(self, mode):
        name = ' '.join(self.name.get().split())
        if not name or len(name) > 32:
            return self.error.config(text='Enter a name')
        if any(p['name'].lower() == name.lower() for p in network.online()):
            return self.error.config(text='That name is taken')
        self.me = network.Me(name, mode)
        self.node = network.Node(self.me, on_chat=lambda c: self.events.put(('chat', c)),
                                 on_text=lambda c, t: self.events.put(('text', c, t)),
                                 on_end=lambda c: self.events.put(('end', c)))
        self.start.destroy()
        key = f'N = {self.me.key["N"]}, e = {self.me.key["e"]}' if mode == 'rsa' else 'ML-KEM-768'
        self.root.title(f'{name} · {LOCK[mode]} ({key})')
        self.main_screen()
        self.heartbeat()

    # ----- main screen -----
    def main_screen(self):
        self.people = tk.Listbox(self.root, bg=PANEL, fg=TEXT, selectbackground=COLOR[self.me.mode],
                                 selectforeground='#000', relief='flat', highlightthickness=0, font=('Segoe UI', 12),
                                 width=16, activestyle='none')
        self.people.pack(side='left', fill='y')
        self.people.bind('<<ListboxSelect>>', self.pick)
        right = tk.Frame(self.root, bg=BG)
        right.pack(side='left', fill='both', expand=True)
        self.title = self.label(right, 'Pick someone', font=('Segoe UI Semibold', 12), anchor='w')
        self.title.pack(fill='x', padx=12, pady=8)
        self.log = tk.Text(right, bg=BG, fg=TEXT, relief='flat', font=FONT, wrap='word', state='disabled',
                           highlightthickness=0, padx=12)
        self.log.pack(fill='both', expand=True)
        self.log.tag_configure('me', foreground=COLOR[self.me.mode])
        self.log.tag_configure('info', foreground=MUTED)
        self.box = tk.Entry(right, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief='flat', font=FONT)
        self.box.pack(fill='x', padx=12, pady=12, ipady=8)
        self.box.bind('<Return>', self.send)

    def heartbeat(self):
        network.announce(self.me, self.node.port)
        self.peers = [p['name'] for p in network.online(self.me.mode, exclude=self.me.id)]
        self.peers += [n for n in self.chats if n not in self.peers]
        shown = [('● ' if n in self.chats else '   ') + n for n in self.peers]
        if list(self.people.get(0, 'end')) != shown:
            self.people.delete(0, 'end')
            self.people.insert('end', *shown)
            if self.current in self.peers:
                self.people.selection_set(self.peers.index(self.current))
        self.root.after(1000, self.heartbeat)

    def pick(self, _):
        if not self.people.curselection():
            return
        self.current = self.peers[self.people.curselection()[0]]
        if self.current not in self.chats:
            port = next((p['port'] for p in network.online(self.me.mode) if p['name'] == self.current), None)
            if port:
                threading.Thread(target=self.dial, args=(self.current, port), daemon=True).start()
        self.show()

    def dial(self, name, port):
        try:
            self.node.dial(port)
        except (OSError, ProtocolError, ValueError, KeyError) as error:
            self.events.put(('note', name, f'Could not connect: {error}'))

    def show(self):
        self.title.config(text=self.current or 'Pick someone')
        self.log.config(state='normal')
        self.log.delete('1.0', 'end')
        for who, text in self.logs.get(self.current, []):
            tag = 'me' if who == 'You' else 'info' if who == '' else ()
            self.log.insert('end', f'{who}: {text}\n' if who else f'{text}\n', tag)
        self.log.config(state='disabled')
        self.log.see('end')

    def add(self, name, who, text):
        self.logs.setdefault(name, []).append((who, text))
        if name == self.current:
            self.show()

    def send(self, _):
        chat, text = self.chats.get(self.current), self.box.get().strip()
        if chat and text:
            chat.send(text)
            self.box.delete(0, 'end')
            self.add(chat.peer, 'You', text)

    # ----- events from network threads -----
    def pump(self):
        while not self.events.empty():
            kind, *rest = self.events.get()
            if kind == 'chat':
                chat = rest[0]
                self.chats[chat.peer] = chat
                self.current = self.current or chat.peer
                self.add(chat.peer, '', 'Connected · AES-256 key locked with ' +
                         (f'RSA N = {chat.header["N"]}' if self.me.mode == 'rsa' else 'X25519 + ML-KEM-768'))
            elif kind == 'text':
                self.add(rest[0].peer, rest[0].peer, rest[1])
            elif kind == 'end':
                if self.chats.get(rest[0].peer) is rest[0]:
                    del self.chats[rest[0].peer]
                    self.add(rest[0].peer, '', 'Disconnected')
            elif kind == 'note':
                self.add(rest[0], '', rest[1])
        self.root.after(100, self.pump)

    def quit(self):
        if self.me:
            network.leave(self.me)
            self.node.stop()
            for chat in self.chats.values():
                chat.close()
        self.root.destroy()


if __name__ == '__main__':
    try:
        __import__('ctypes').windll.shcore.SetProcessDpiAwareness(1)  # sharp text on scaled screens
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    ChatApp(root)
    root.mainloop()
