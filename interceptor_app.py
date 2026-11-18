"""ACG Interceptor: passively captures every ACG Chat conversation on this computer.

Packets are sniffed from the loopback interface with Npcap (the capture driver
Wireshark uses) and rebuilt into chat frames by capture.py. Each conversation
gets its own tab. RSA conversations can be cracked with a simulated run of
Shor's algorithm; post-quantum conversations cannot.
"""
from datetime import datetime
import math
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk

from chat_protocol import decrypt_record, is_hybrid, is_toy_rsa, recover_master
from intercept import CaptureQueue
from peer_net import CHAT_PORTS

HERE = Path(__file__).resolve().parent
INTERFACE = r'\Device\NPF_Loopback'
BG, PANEL, LINE = '#0f141a', '#171f28', '#26313d'
TEXT, MUTED, WHITE = '#e6e9ed', '#8b96a3', '#ffffff'
RED, AMBER, TEAL = '#ff6b4a', '#f2b544', '#2dd4bf'
FONT, FONT_BOLD, MONO = ('Segoe UI', 10), ('Segoe UI Semibold', 10), ('Consolas', 10)


def crack_session(header, progress):
    """Run Shor on the captured public key, rebuild d, unlock the AES key."""
    from shor import crack
    modulus, exponent = header['N'], header['e']
    evidence = crack(modulus, progress=progress)
    p, q = evidence['factors']
    phi = (p - 1) * (q - 1)
    private_exponent = pow(exponent, -1, phi)
    master = recover_master(header, private_exponent)
    return evidence, phi, private_exponent, master


class SessionTab:
    def __init__(self, app, session_id, session):
        self.app, self.session_id, self.session = app, session_id, session
        self.header = session.header
        self.master = None
        self.decrypting = False
        self.shown = 0
        self.rows = {}
        header = self.header
        self.frame = tk.Frame(app.notebook, bg=BG)
        title = f'{header["alice"]}  ↔  {header["bob"]}'
        app.notebook.add(self.frame, text=f'  {title}  ')

        top = tk.Frame(self.frame, bg=BG)
        top.pack(fill='x', padx=16, pady=(14, 4))
        tk.Label(top, text=title, bg=BG, fg=WHITE, font=('Segoe UI Semibold', 16)).pack(side='left')
        self.state = tk.Label(top, text='', fg='#0b0f14', font=('Segoe UI Semibold', 9), padx=8, pady=2)
        self.state.pack(side='left', padx=12)
        if is_toy_rsa(header):
            lock = f'AES-256 key locked with {header["bob"]}\'s RSA key  N = {header["N"]},  e = {header["e"]}'
            detail = ('Captured handshake: ' + str(len(header['wrapped_key_digits'])) + ' RSA-encrypted blocks  '
                      + ' '.join(str(x) for x in header['wrapped_key_digits'][:14]) + ' …')
            self._set_state('LOCKED', AMBER)
        else:
            lock = 'AES-256 key from X25519 + ML-KEM-768 (hybrid key exchange)'
            detail = ('Captured handshake: X25519 ephemeral key ' + header['x25519_ephemeral_hex'][:24]
                      + '…  ·  ML-KEM-768 ciphertext ' + header['mlkem_ciphertext_hex'][:24] + '… (1,088 bytes)')
            self._set_state('LOCKED', AMBER)
        tk.Label(self.frame, text=lock, bg=BG, fg=TEXT, font=FONT, anchor='w').pack(fill='x', padx=16)
        tk.Label(self.frame, text=detail, bg=BG, fg=MUTED, font=('Consolas', 9), anchor='w').pack(fill='x', padx=16, pady=(2, 10))

        body = tk.Frame(self.frame, bg=BG)
        body.pack(fill='both', expand=True, padx=16, pady=(0, 14))
        left = tk.Frame(body, bg=BG)
        left.pack(side='left', fill='both', expand=True)
        tk.Label(left, text='CAPTURED TRAFFIC', bg=BG, fg=MUTED, font=('Segoe UI Semibold', 9)).pack(anchor='w')
        columns = ('time', 'direction', 'ciphertext', 'plaintext')
        self.tree = ttk.Treeview(left, columns=columns, show='headings', style='Cap.Treeview')
        for column, title_text, width in (('time', 'Time', 80), ('direction', 'From → To', 130),
                                          ('ciphertext', 'Ciphertext (AES-256-GCM)', 260), ('plaintext', 'Plaintext', 220)):
            self.tree.heading(column, text=title_text, anchor='w')
            self.tree.column(column, width=width, anchor='w', stretch=column in ('ciphertext', 'plaintext'))
        self.tree.tag_configure('plain', foreground=TEAL)
        self.tree.pack(fill='both', expand=True, pady=(4, 0))

        right = tk.Frame(body, bg=PANEL, width=470)
        right.pack(side='left', fill='y', padx=(14, 0))
        right.pack_propagate(False)
        tk.Label(right, text='ATTACK', bg=PANEL, fg=MUTED, font=('Segoe UI Semibold', 9)).pack(anchor='w', padx=14, pady=(12, 6))
        buttons = tk.Frame(right, bg=PANEL)
        buttons.pack(fill='x', padx=14)
        self.shor_button = app.button(buttons, "Run Shor's algorithm", self.run_shor, RED)
        self.shor_button.pack(side='left')
        self.decrypt_button = app.button(buttons, 'Decrypt', self.decrypt, TEAL)
        self.decrypt_button.pack(side='left', padx=8)
        app.enable(self.decrypt_button, False)
        self.chart = tk.Canvas(right, bg=PANEL, height=150, highlightthickness=0)
        self.chart.pack(fill='x', padx=14, pady=(12, 0))
        self.log = tk.Text(right, bg=PANEL, fg=TEXT, relief='flat', wrap='word', font=('Consolas', 10),
                           highlightthickness=0, padx=0, pady=6, state='disabled')
        self.log.pack(fill='both', expand=True, padx=14, pady=(4, 12))
        for tag, color in (('muted', MUTED), ('good', TEAL), ('bad', RED), ('warn', AMBER), ('white', WHITE)):
            self.log.tag_configure(tag, foreground=color)
        self.write('Captured session ' + session_id[:8] + '. Messages are AES-256-GCM ciphertext.', 'muted')
        if is_toy_rsa(header):
            self.write(f'The AES key is protected only by RSA with N = {header["N"]}.', 'muted')
            self.write("Press Run Shor's algorithm to factor N.", 'muted')
        else:
            self.write('The AES key is protected by X25519 + ML-KEM-768.', 'muted')
        self.refresh_rows()

    def _set_state(self, text, color):
        self.state.config(text=text, bg=color)

    def write(self, text, tag=None):
        self.log.config(state='normal')
        self.log.insert('end', text + '\n', tag or ())
        self.log.config(state='disabled')
        self.log.see('end')

    # ----- traffic -----
    def refresh_rows(self):
        records = self.session.records
        for record in records[self.shown:]:
            frame = record.frame
            sender = self.header['alice'] if frame['direction'] == 'a_to_b' else self.header['bob']
            receiver = self.header['bob'] if frame['direction'] == 'a_to_b' else self.header['alice']
            stamp = datetime.fromtimestamp(record.time_ns / 1e9).strftime('%H:%M:%S')
            cipher = frame['ciphertext_and_tag_hex']
            item = self.tree.insert('', 'end', values=(stamp, f'{sender} → {receiver}',
                                                      cipher[:44] + ('…' if len(cipher) > 44 else ''), '🔒 encrypted'))
            self.rows[id(record)] = (item, record)
        self.shown = len(records)
        if self.decrypting:
            self._decrypt_rows()

    def _decrypt_rows(self):
        for item, record in self.rows.values():
            if self.tree.set(item, 'plaintext').startswith('🔒'):
                try:
                    text = decrypt_record(self.header, self.master, record.frame)
                    self.tree.set(item, 'plaintext', text)
                    self.tree.item(item, tags=('plain',))
                except ValueError as error:
                    self.tree.set(item, 'plaintext', f'⚠ {error}')

    # ----- attack -----
    def run_shor(self):
        if is_hybrid(self.header):
            self.app.enable(self.shor_button, False)
            self.write('')
            self.write("Shor's algorithm works by finding a hidden repeating period. RSA has one (factoring N), and so do classic Diffie-Hellman and elliptic curves.", 'white')
            self.write('')
            self.write('X25519 on its own would fall to Shor, but this session key also needs the ML-KEM-768 secret. ML-KEM is a lattice problem (Module-LWE) with no hidden period, so Shor has nothing to measure.', 'white')
            self.write('')
            self.write('No known quantum attack recovers the key. Messages stay encrypted.', 'good')
            self._set_state('QUANTUM-SAFE', TEAL)
            self._draw_blocked()
            return
        self.app.enable(self.shor_button, False)
        modulus = self.header['N']
        self.write('')
        self.write(f'Target: N = {modulus} ({modulus.bit_length()}-bit RSA modulus)', 'white')
        self._set_state('CRACKING …', RED)
        threading.Thread(target=self._crack_worker, daemon=True).start()

    def _crack_worker(self):
        post = self.app.events.put
        try:
            result = crack_session(self.header, lambda message: post(('log', self, message, 'muted')))
        except Exception as error:  # surfaced in the tab, never swallowed
            post(('failed', self, str(error)))
            return
        post(('cracked', self, result))

    def on_cracked(self, result):
        evidence, phi, d, master = result
        n, a, r = evidence['modulus'], evidence['base'], evidence['order']
        p, q = evidence['factors']
        half = pow(a, r // 2, n)
        self.write(f'Simulated {evidence["counting_qubits"] + evidence["work_qubits"]} qubits, '
                   f'{evidence["shots"]} shots, {evidence["elapsed_seconds"]:.1f} s', 'muted')
        self.write(f'Measured y = {int(evidence["sample"], 2)}  →  y / 2^{evidence["counting_qubits"]} ≈ {evidence["phase"]:.4f}')
        self.write(f'Continued fraction ≈ {evidence["convergent"][0]}/{evidence["convergent"][1]}  →  period r = {r}')
        self.write(f'{a}^{r // 2} mod {n} = {half}  →  gcd({half - 1}, {n}) and gcd({half + 1}, {n})')
        self.write(f'N = {n} = {p} × {q}', 'bad')
        self.write(f'φ(N) = {phi}   private key d = {self.header["e"]}⁻¹ mod {phi} = {d}', 'bad')
        self.write(f'Unlocked {len(self.header["wrapped_key_digits"])} RSA blocks → AES-256 session key', 'bad')
        self.write(f'{master.hex()}', 'warn')
        self.write('Press Decrypt to read the conversation.', 'good')
        self.master = master
        self._set_state('KEY CRACKED', RED)
        self.app.enable(self.decrypt_button, True)
        self._draw_histogram(evidence)

    def on_failed(self, error):
        self.write(f'Attack failed: {error}', 'bad')
        self.app.enable(self.shor_button, True)
        self._set_state('LOCKED', AMBER)

    def decrypt(self):
        if self.master is None:
            return
        self.decrypting = True
        self.app.enable(self.decrypt_button, False)
        self._decrypt_rows()
        self.write('Decrypting every captured message (and new ones as they arrive).', 'good')
        self._set_state('DECRYPTED', RED)

    def _draw_histogram(self, evidence):
        canvas = self.chart
        canvas.delete('all')
        canvas.update_idletasks()
        width, height = max(canvas.winfo_width(), 400), 150
        counts = sorted(evidence['counts'].items(), key=lambda kv: -kv[1])[:12]
        top = counts[0][1]
        bar = (width - 10) / len(counts)
        canvas.create_text(0, 8, text='Most frequent measurements (counting register)', fill=MUTED,
                           anchor='w', font=('Segoe UI', 8))
        for index, (bits, count) in enumerate(counts):
            x0 = 4 + index * bar
            h = (height - 46) * count / top
            color = RED if bits == evidence['sample'] else '#3b4a5a'
            canvas.create_rectangle(x0 + 3, height - 22 - h, x0 + bar - 3, height - 22, fill=color, width=0)
            canvas.create_text(x0 + bar / 2, height - 12, text=str(int(bits, 2)), fill=MUTED, font=('Consolas', 8))

    def _draw_blocked(self):
        canvas = self.chart
        canvas.delete('all')
        canvas.update_idletasks()
        width = max(canvas.winfo_width(), 400)
        canvas.create_text(width / 2, 60, text='No period to measure', fill=TEAL, font=('Segoe UI Semibold', 16))
        canvas.create_text(width / 2, 90, text='Shor has nothing to attack in ML-KEM-768', fill=MUTED, font=FONT)


class InterceptorApp:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.tabs = {}
        self.capture_process = None
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        self.capture_path = HERE / 'captures' / f'interceptor-{stamp}.jsonl'
        self.pcap_path = HERE / 'captures' / f'interceptor-{stamp}.pcap'
        self.queue = CaptureQueue(self.capture_path, output=lambda message: None)
        root.title('ACG Interceptor')
        root.configure(bg=BG)
        root.geometry('1280x780+60+40')
        root.minsize(1000, 620)
        root.protocol('WM_DELETE_WINDOW', self.quit)
        self._style()
        self._layout()
        self._start_capture()
        root.after(400, self._poll)
        root.after(100, self._pump)

    def _style(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('TNotebook', background=BG, borderwidth=0, tabmargins=(12, 6, 12, 0))
        style.configure('TNotebook.Tab', background=PANEL, foreground=MUTED, padding=(14, 7), font=FONT_BOLD, borderwidth=0)
        style.map('TNotebook.Tab', background=[('selected', LINE)], foreground=[('selected', WHITE)])
        style.configure('Cap.Treeview', background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=26,
                        font=('Consolas', 10), borderwidth=0)
        style.configure('Cap.Treeview.Heading', background=LINE, foreground=MUTED, font=('Segoe UI Semibold', 9), relief='flat')
        style.map('Cap.Treeview', background=[('selected', '#2b3846')])

    def button(self, parent, text, command, color):
        button = tk.Button(parent, text=text, command=command, bg=color, fg='#0b0f14', activebackground=color,
                           disabledforeground='#5d6873', relief='flat', font=('Segoe UI Semibold', 10),
                           padx=14, pady=6, cursor='hand2', bd=0)
        button.color = color
        return button

    @staticmethod
    def enable(button, on):
        button.config(state='normal' if on else 'disabled', bg=button.color if on else LINE,
                      cursor='hand2' if on else 'arrow')

    def _layout(self):
        top = tk.Frame(self.root, bg=PANEL)
        top.pack(fill='x')
        tk.Label(top, text='INTERCEPTOR', bg=PANEL, fg=WHITE, font=('Segoe UI Semibold', 15)).pack(side='left', padx=16, pady=12)
        self.status_dot = tk.Label(top, text='●', bg=PANEL, fg=AMBER, font=('Segoe UI', 13))
        self.status_dot.pack(side='left')
        self.status = tk.Label(top, text='Starting packet capture …', bg=PANEL, fg=TEXT, font=FONT)
        self.status.pack(side='left', padx=6)
        self.counts = tk.Label(top, text='', bg=PANEL, fg=MUTED, font=FONT)
        self.counts.pack(side='right', padx=16)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)
        self.waiting = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.waiting, text='  Waiting  ')
        tk.Label(self.waiting, text='Listening for ACG Chat conversations', bg=BG, fg=WHITE,
                 font=('Segoe UI Semibold', 18)).pack(pady=(140, 8))
        tk.Label(self.waiting, text='Open two ACG Chat windows and start a conversation.\n'
                                    'Each conversation captured from now on appears here as its own tab.\n\n'
                                    'Conversations that started before the Interceptor was opened cannot be read.',
                 bg=BG, fg=MUTED, font=('Segoe UI', 11), justify='center').pack()
        self.footer = tk.Label(self.root, text=f'Capture file: {self.capture_path}    ·    Wireshark file: {self.pcap_path}',
                               bg=BG, fg=MUTED, font=('Segoe UI', 8), anchor='w')
        self.footer.pack(fill='x', padx=12, pady=4)

    def _start_capture(self):
        self.capture_path.parent.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, str(HERE / 'capture.py'), '--interface', INTERFACE,
                   '--port-range', f'{CHAT_PORTS[0]}-{CHAT_PORTS[1]}',
                   '--output', str(self.capture_path), '--pcap-out', str(self.pcap_path),
                   '--parent-pid', str(os.getpid())]
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        try:
            self.capture_process = subprocess.Popen(command, cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                    text=True, encoding='utf-8', errors='replace', creationflags=flags)
        except OSError as error:
            self._capture_failed(str(error))
            return
        threading.Thread(target=self._read_capture_output, daemon=True).start()

    def _read_capture_output(self):
        process = self.capture_process
        try:
            for line in process.stdout:
                self.events.put(('capture_line', line.strip()))
        except (OSError, ValueError):
            pass  # pipe closed while the window shuts down
        self.events.put(('capture_exit', process.wait()))

    def _capture_failed(self, message):
        self.status_dot.config(fg=RED)
        self.status.config(text=f'Capture stopped: {message}')

    def _poll(self):
        try:
            self.queue.refresh()
        except ValueError as error:
            self._capture_failed(str(error))
        for session_id, session in self.queue.sessions.items():
            if session_id not in self.tabs:
                if not self.tabs:
                    self.notebook.forget(self.waiting)
                tab = self.tabs[session_id] = SessionTab(self, session_id, session)
                self.notebook.select(tab.frame)
            else:
                self.tabs[session_id].refresh_rows()
        messages = sum(len(s.records) for s in self.queue.sessions.values())
        self.counts.config(text=f'{len(self.queue.sessions)} conversations  ·  {messages} messages captured')
        self.root.after(400, self._poll)

    def _pump(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == 'capture_line':
                    if event[1].startswith('Capture ready'):
                        self.status_dot.config(fg=TEAL)
                        self.status.config(text=f'Capturing loopback traffic on TCP ports {CHAT_PORTS[0]}–{CHAT_PORTS[1]} (Npcap)')
                    elif event[1].lower().startswith('capture error'):
                        self._capture_failed(event[1])
                elif kind == 'capture_exit':
                    if self.capture_process is not None:
                        self._capture_failed(f'capture process exited ({event[1]})')
                elif kind == 'log':
                    event[1].write(event[2], event[3])
                elif kind == 'cracked':
                    event[1].on_cracked(event[2])
                elif kind == 'failed':
                    event[1].on_failed(event[2])
        except queue.Empty:
            pass
        self.root.after(100, self._pump)

    def quit(self):
        process, self.capture_process = self.capture_process, None
        if process is not None and process.poll() is None:
            process.terminate()
        self.root.destroy()


def main():
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    InterceptorApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
