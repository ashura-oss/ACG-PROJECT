"""ACG Interceptor. Sniffs every ACG Chat conversation on this computer (Npcap loopback)."""
import queue
import threading
import tkinter as tk
from tkinter import ttk

import network
import shor
from protocol import PQC_VERSION, ProtocolError, decode_frame, decrypt_message, unlock_rsa_key, validate_header

BG, PANEL, TEXT, MUTED = '#111418', '#1b2027', '#e8eaed', '#8a939c'
RED, TEAL = '#ff6b4a', '#2dd4bf'
MONO, FONT = ('Consolas', 10), ('Segoe UI', 11)
INTERFACE = r'\Device\NPF_Loopback'


class Stream:
    """Rebuilds one direction of a TCP connection into newline-separated frames."""

    def __init__(self, next_seq):
        self.next, self.pending, self.buffer = next_seq, {}, b''

    def feed(self, seq, data):
        self.pending[seq] = data
        while True:
            for seq, data in list(self.pending.items()):
                skip = (self.next - seq) % 2 ** 32
                if skip < len(data):             # in order, or a retransmit with new bytes
                    self.buffer += data[skip:]
                    self.next = (self.next + len(data) - skip) % 2 ** 32
                if skip < 2 ** 31:               # consumed or old: drop it
                    del self.pending[seq]
                    break
            else:
                break
        *lines, self.buffer = self.buffer.split(b'\n')
        return [line + b'\n' for line in lines]


class Sniffer:
    def __init__(self, on_frame):
        self.on_frame, self.streams = on_frame, {}

    def start(self):
        from scapy.all import AsyncSniffer
        self.sniffer = AsyncSniffer(iface=INTERFACE, store=False, prn=self.packet,
                                    filter=f'tcp portrange {network.PORTS[0]}-{network.PORTS[-1]}')
        self.sniffer.start()

    def packet(self, pkt):
        from scapy.layers.inet import IP, TCP
        if IP not in pkt or TCP not in pkt:
            return
        ip, tcp = pkt[IP], pkt[TCP]
        if tcp.dport in network.PORTS and tcp.sport not in network.PORTS:
            conn, direction = (tcp.sport, tcp.dport), 'a_to_b'
        elif tcp.sport in network.PORTS and tcp.dport not in network.PORTS:
            conn, direction = (tcp.dport, tcp.sport), 'b_to_a'
        else:
            return
        if tcp.flags & 0x02:                     # SYN: a new connection starts here
            self.streams[conn, direction] = Stream((tcp.seq + 1) % 2 ** 32)
            return
        stream = self.streams.get((conn, direction))
        payload = bytes(tcp.payload)[:ip.len - ip.ihl * 4 - tcp.dataofs * 4]
        if stream is None or not payload:
            return
        for line in stream.feed(tcp.seq, payload):
            try:
                self.on_frame(conn, direction, decode_frame(line))
            except ProtocolError:
                pass

    def stop(self):
        try:
            self.sniffer.stop()
        except Exception:
            pass


class Tab:
    def __init__(self, app, header):
        self.app, self.header, self.key, self.frames = app, header, None, []
        self.rsa = header['version'] != PQC_VERSION
        self.frame = tk.Frame(app.tabs, bg=BG)
        app.tabs.add(self.frame, text=f'  {header["alice"]} ↔ {header["bob"]}  ')
        lock = f'RSA  N = {header["N"]}, e = {header["e"]}' if self.rsa else 'X25519 + ML-KEM-768'
        tk.Label(self.frame, text=f'AES-256 key locked with {lock}', bg=BG, fg=MUTED, font=FONT,
                 anchor='w').pack(fill='x', padx=14, pady=(12, 6))
        self.list = tk.Text(self.frame, bg=PANEL, fg=TEXT, relief='flat', font=MONO, height=12,
                            state='disabled', highlightthickness=0, padx=10, pady=8)
        self.list.pack(fill='both', expand=True, padx=14)
        self.list.tag_configure('plain', foreground=TEAL)
        self.button = tk.Button(self.frame, text="Crack with Shor's", command=self.crack, bg=RED, fg='#000',
                                relief='flat', font=('Segoe UI Semibold', 11), padx=16, pady=6, bd=0, cursor='hand2')
        self.button.pack(anchor='w', padx=14, pady=10)
        self.result = tk.Label(self.frame, text='', bg=BG, fg=TEXT, font=MONO, justify='left', anchor='w')
        self.result.pack(fill='x', padx=14, pady=(0, 14))

    def add(self, frame):
        self.frames.append(frame)
        self.draw()

    def draw(self):
        self.list.config(state='normal')
        self.list.delete('1.0', 'end')
        for frame in self.frames:
            who = self.header['alice' if frame['direction'] == 'a_to_b' else 'bob']
            if self.key:
                try:
                    self.list.insert('end', f'{who:>10}  {decrypt_message(self.header, self.key, frame)}\n', 'plain')
                    continue
                except ProtocolError:
                    pass
            self.list.insert('end', f'{who:>10}  {frame["ciphertext"][:48]}…\n')
        self.list.config(state='disabled')

    def crack(self):
        self.button.config(state='disabled', bg=PANEL)
        if not self.rsa:
            self.result.config(fg=TEAL, text="Can't crack it. Shor's needs a hidden period to find.\n"
                                             'ML-KEM-768 is a lattice problem with none. Messages stay encrypted.')
            return
        self.result.config(fg=MUTED, text=f'Running Shor\'s on N = {self.header["N"]} …')
        threading.Thread(target=self.work, daemon=True).start()

    def work(self):
        try:
            found = shor.crack(self.header['N'])
            p, q = found['factors']
            d = pow(self.header['e'], -1, (p - 1) * (q - 1))
            self.app.events.put((self.cracked, found, d, unlock_rsa_key(self.header, d)))
        except Exception as error:
            self.app.events.put((self.failed, str(error)))

    def cracked(self, found, d, key):
        self.key = key
        p, q = found['factors']
        self.result.config(fg=RED, text=(
            f'Measured y = {found["y"]}  →  period r = {found["r"]}  (a = {found["a"]}, {found["qubits"]} qubits)\n'
            f'N = {found["n"]} = {p} × {q}  →  private key d = {d}\n'
            f'AES-256 key recovered in {found["seconds"]:.1f} s. Messages decrypted.'))
        self.draw()

    def failed(self, error):
        self.result.config(fg=RED, text=f'Failed: {error}')
        self.button.config(state='normal', bg=RED)


class InterceptorApp:
    def __init__(self, root):
        self.root, self.events, self.chats = root, queue.Queue(), {}
        root.title('ACG Interceptor')
        root.configure(bg=BG)
        root.geometry('900x560')
        root.protocol('WM_DELETE_WINDOW', self.quit)
        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure('TNotebook', background=BG, borderwidth=0)
        style.configure('TNotebook.Tab', background=PANEL, foreground=MUTED, padding=(12, 6), borderwidth=0)
        style.map('TNotebook.Tab', background=[('selected', BG)], foreground=[('selected', TEXT)])
        self.status = tk.Label(root, text='Listening on loopback …', bg=BG, fg=MUTED, font=FONT, anchor='w')
        self.status.pack(fill='x', padx=14, pady=8)
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill='both', expand=True)
        self.sniffer = Sniffer(lambda *args: self.events.put((self.frame,) + args))
        try:
            self.sniffer.start()
        except Exception as error:
            self.status.config(fg=RED, text=f'Cannot capture: {error}  (is Npcap installed?)')
        root.after(100, self.pump)

    def frame(self, conn, direction, frame):
        if frame.get('type') == 'session' and direction == 'a_to_b':
            try:
                self.chats[conn] = Tab(self, validate_header(frame.get('header')))
            except ProtocolError:
                return
            self.tabs.select(self.chats[conn].frame)
            self.status.config(text=f'{len(self.chats)} conversation(s) captured')
        elif frame.get('type') == 'message' and conn in self.chats:
            self.chats[conn].add(frame)

    def pump(self):
        while not self.events.empty():
            handler, *args = self.events.get()
            handler(*args)
        self.root.after(100, self.pump)

    def quit(self):
        self.sniffer.stop()
        self.root.destroy()


if __name__ == '__main__':
    try:
        __import__('ctypes').windll.shcore.SetProcessDpiAwareness(1)  # sharp text on scaled screens
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    InterceptorApp(root)
    root.mainloop()
