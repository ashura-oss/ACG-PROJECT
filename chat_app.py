"""ACG Chat: desktop chatter. Open as many windows as you like; they find each other."""
import queue
import random
import threading
import tkinter as tk
from tkinter import ttk

from chat_protocol import ProtocolError, validate_name
from peer_net import MODE_LABELS, Identity, Node, Registry

BG, PANEL, SIDE, LINE = '#0f141a', '#171f28', '#121920', '#26313d'
TEXT, MUTED, WHITE = '#e6e9ed', '#8b96a3', '#ffffff'
ACCENT = {'rsa': '#ff6b4a', 'pqc': '#2dd4bf'}
BUBBLE_ME = {'rsa': '#5a2a20', 'pqc': '#0f4a46'}
BUBBLE_THEM = '#222c37'
FONT, FONT_BOLD, MONO = ('Segoe UI', 11), ('Segoe UI Semibold', 11), ('Consolas', 10)


class ChatApp:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.registry = Registry()
        self.identity = self.node = None
        self.chats = {}          # peer name -> {'session': Session | None, 'lines': [(kind, who, text)], 'unread': int}
        self.online = []         # registry entries for peers in the same mode
        self.current = None
        root.title('ACG Chat')
        root.configure(bg=BG)
        root.geometry(f'860x580+{random.randint(40, 260)}+{random.randint(40, 180)}')
        root.minsize(720, 460)
        root.protocol('WM_DELETE_WINDOW', self.quit)
        self._style()
        self._onboarding()
        root.after(100, self._pump)

    # ---------- look ----------
    def _style(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('TFrame', background=BG)
        style.configure('Vertical.TScrollbar', background=LINE, troughcolor=BG, bordercolor=BG, arrowcolor=MUTED,
                        darkcolor=LINE, lightcolor=LINE, gripcount=0)
        style.map('Vertical.TScrollbar', background=[('active', '#33414f')])

    def _button(self, parent, text, command, color):
        return tk.Button(parent, text=text, command=command, bg=color, fg='#0b0f14', activebackground=color,
                         relief='flat', font=FONT_BOLD, padx=18, pady=8, cursor='hand2', bd=0)

    # ---------- onboarding ----------
    def _onboarding(self):
        self.onboard = tk.Frame(self.root, bg=BG)
        self.onboard.place(relx=0.5, rely=0.5, anchor='center')
        tk.Label(self.onboard, text='ACG Chat', bg=BG, fg=WHITE, font=('Segoe UI Semibold', 26)).pack(anchor='w')
        tk.Label(self.onboard, text='Encrypted with AES-256. Choose how the AES key is locked.',
                 bg=BG, fg=MUTED, font=FONT).pack(anchor='w', pady=(0, 22))
        tk.Label(self.onboard, text='YOUR NAME', bg=BG, fg=MUTED, font=('Segoe UI Semibold', 9)).pack(anchor='w')
        self.name_var = tk.StringVar()
        entry = tk.Entry(self.onboard, textvariable=self.name_var, bg=PANEL, fg=TEXT, insertbackground=TEXT,
                         relief='flat', font=('Segoe UI', 13), width=32)
        entry.pack(anchor='w', fill='x', ipady=7, pady=(4, 18))
        entry.focus_set()
        entry.bind('<Return>', lambda _: self._start())
        tk.Label(self.onboard, text='LOCK FOR THE AES KEY', bg=BG, fg=MUTED,
                 font=('Segoe UI Semibold', 9)).pack(anchor='w')
        self.mode_var = tk.StringVar(value='rsa')
        notes = {'rsa': 'A new random 7-bit RSA key. Shor\'s algorithm can crack it.',
                 'pqc': 'Lattice-based key exchange. No known quantum attack.'}
        for mode in ('rsa', 'pqc'):
            card = tk.Frame(self.onboard, bg=PANEL, padx=12, pady=8)
            card.pack(anchor='w', fill='x', pady=(6, 0))
            tk.Radiobutton(card, text=MODE_LABELS[mode], variable=self.mode_var, value=mode, bg=PANEL, fg=TEXT,
                           selectcolor=BG, activebackground=PANEL, activeforeground=ACCENT[mode],
                           font=FONT_BOLD, anchor='w').pack(anchor='w')
            tk.Label(card, text=notes[mode], bg=PANEL, fg=MUTED, font=('Segoe UI', 10)).pack(anchor='w', padx=24)
        self.onboard_error = tk.Label(self.onboard, text='', bg=BG, fg=ACCENT['rsa'], font=FONT)
        self.onboard_error.pack(anchor='w', pady=(12, 0))
        self._button(self.onboard, 'Start chatting', self._start, '#e6e9ed').pack(anchor='w', pady=(8, 0))

    def _start(self):
        name = ' '.join(self.name_var.get().split())
        try:
            validate_name(name)
        except ProtocolError:
            self.onboard_error.config(text='Enter a name of 1 to 32 characters.')
            return
        if self.registry.name_taken(name):
            self.onboard_error.config(text=f'Someone online is already called {name}.')
            return
        mode = self.mode_var.get()
        self.identity = Identity(name, mode)
        try:
            self.node = Node(self.identity, on_session=lambda s: self.events.put(('session', s)),
                             on_message=lambda s, t: self.events.put(('message', s, t)),
                             on_closed=lambda s, e: self.events.put(('closed', s, e)),
                             on_error=lambda e: self.events.put(('notice', e)))
        except OSError as error:
            self.onboard_error.config(text=str(error))
            return
        self.onboard.destroy()
        self.root.title(f'ACG Chat  ·  {name}  ·  {"RSA" if mode == "rsa" else "Post-quantum"}')
        self._main_ui()
        self._heartbeat()

    # ---------- main screen ----------
    def _main_ui(self):
        mode, accent = self.identity.mode, ACCENT[self.identity.mode]
        top = tk.Frame(self.root, bg=PANEL, height=56)
        top.pack(fill='x')
        tk.Label(top, text=self.identity.name, bg=PANEL, fg=WHITE, font=('Segoe UI Semibold', 14)).pack(side='left', padx=(16, 10), pady=12)
        tk.Label(top, text=' RSA · CRACKABLE ' if mode == 'rsa' else ' POST-QUANTUM ', bg=accent, fg='#0b0f14',
                 font=('Segoe UI Semibold', 9)).pack(side='left')
        tk.Label(top, text=self.identity.public_summary(), bg=PANEL, fg=MUTED, font=MONO).pack(side='right', padx=16)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill='both', expand=True)
        side = tk.Frame(body, bg=SIDE, width=230)
        side.pack(side='left', fill='y')
        side.pack_propagate(False)
        tk.Label(side, text=f'ONLINE · {"RSA" if mode == "rsa" else "POST-QUANTUM"}', bg=SIDE, fg=MUTED,
                 font=('Segoe UI Semibold', 9)).pack(anchor='w', padx=14, pady=(14, 6))
        self.peer_list = tk.Listbox(side, bg=SIDE, fg=TEXT, selectbackground=LINE, selectforeground=WHITE,
                                    highlightthickness=0, bd=0, font=('Segoe UI', 12), activestyle='none')
        self.peer_list.pack(fill='both', expand=True, padx=8)
        self.peer_list.bind('<<ListboxSelect>>', self._on_select)
        self.side_hint = tk.Label(side, text='Waiting for others to join.\nOpen another ACG Chat window\nwith the same lock.',
                                  bg=SIDE, fg=MUTED, font=('Segoe UI', 9), justify='left')
        self.side_hint.pack(anchor='w', padx=14, pady=12)

        main = tk.Frame(body, bg=BG)
        main.pack(side='left', fill='both', expand=True)
        self.chat_title = tk.Label(main, text='Pick someone on the left', bg=BG, fg=WHITE,
                                   font=('Segoe UI Semibold', 13), anchor='w')
        self.chat_title.pack(fill='x', padx=16, pady=(12, 0))
        self.chat_lock = tk.Label(main, text='', bg=BG, fg=MUTED, font=MONO, anchor='w')
        self.chat_lock.pack(fill='x', padx=16, pady=(0, 8))
        holder = tk.Frame(main, bg=BG)
        holder.pack(fill='both', expand=True, padx=(16, 8))
        self.log = tk.Text(holder, bg=BG, fg=TEXT, relief='flat', wrap='word', font=FONT, padx=4, pady=4,
                           state='disabled', cursor='arrow', highlightthickness=0)
        scroll = ttk.Scrollbar(holder, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.log.pack(side='left', fill='both', expand=True)
        self.log.tag_configure('me', justify='right', lmargin1=140, lmargin2=140, rmargin=8,
                               background=BUBBLE_ME[mode], foreground=WHITE, spacing1=8, spacing3=2)
        self.log.tag_configure('them', justify='left', lmargin1=8, lmargin2=8, rmargin=140,
                               background=BUBBLE_THEM, foreground=WHITE, spacing1=8, spacing3=2)
        self.log.tag_configure('who_me', justify='right', foreground=MUTED, font=('Segoe UI', 8), rmargin=8, spacing1=10)
        self.log.tag_configure('who_them', justify='left', foreground=MUTED, font=('Segoe UI', 8), lmargin1=8, spacing1=10)
        self.log.tag_configure('sys', justify='center', foreground=MUTED, font=('Segoe UI', 9), spacing1=10, spacing3=4)
        row = tk.Frame(main, bg=PANEL)
        row.pack(fill='x', padx=16, pady=12)
        self.entry = tk.Entry(row, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief='flat', font=('Segoe UI', 12),
                              state='disabled', disabledbackground=PANEL)
        self.entry.pack(side='left', fill='x', expand=True, ipady=9, padx=(12, 8))
        self.entry.bind('<Return>', lambda _: self._send())
        self.send_button = self._button(row, 'Send', self._send, accent)
        self.send_button.pack(side='right', padx=6, pady=6)

    def _heartbeat(self):
        if self.node is None:
            return
        try:
            self.registry.announce(self.identity, self.node.port)
            self.online = self.registry.peers(mode=self.identity.mode, exclude=self.identity.peer_id)
            self._render_peers()
        except OSError:
            pass  # transient file contention; keep the heartbeat alive
        finally:
            self.root.after(1000, self._heartbeat)

    def _peer_names(self):
        names = [entry['name'] for entry in self.online]
        names += [name for name, chat in self.chats.items() if chat['session'] and name not in names]
        return names

    def _render_peers(self):
        names = self._peer_names()
        labels = []
        for name in names:
            chat = self.chats.get(name)
            mark = '●  ' if chat and chat['session'] else '○  '
            unread = f'   ({chat["unread"]})' if chat and chat['unread'] else ''
            labels.append(f'{mark}{name}{unread}')
        if list(self.peer_list.get(0, 'end')) != labels:
            self.peer_list.delete(0, 'end')
            for label in labels:
                self.peer_list.insert('end', label)
        if self.current in names:
            index = names.index(self.current)
            if self.peer_list.curselection() != (index,):
                self.peer_list.selection_clear(0, 'end')
                self.peer_list.selection_set(index)
        self.side_hint.config(text='' if names else 'Waiting for others to join.\nOpen another ACG Chat window\nwith the same lock.')

    def _on_select(self, _event):
        selection = self.peer_list.curselection()
        names = self._peer_names()
        if not selection or selection[0] >= len(names):
            return
        self._open(names[selection[0]])

    def _chat(self, name):
        return self.chats.setdefault(name, {'session': None, 'lines': [], 'unread': 0, 'dialling': False})

    def _open(self, name):
        self.current = name
        chat = self._chat(name)
        chat['unread'] = 0
        if chat['session'] is None and not chat['dialling']:
            entry = next((e for e in self.online if e['name'] == name), None)
            if entry is not None:
                chat['dialling'] = True
                chat['lines'].append(('sys', '', f'Connecting to {name} and exchanging the AES key ...'))
                threading.Thread(target=self._dial, args=(name, entry['port']), daemon=True).start()
        self._render_chat()
        self._render_peers()

    def _dial(self, name, port):
        try:
            self.node.dial(port)
        except (OSError, ProtocolError, ValueError) as error:
            self.events.put(('dial_failed', name, str(error)))

    def _lock_text(self, session):
        header = session.header
        if self.identity.mode == 'rsa':
            return (f'AES-256 key locked with {header["bob"]}\'s RSA key  N = {header["N"]}, e = {header["e"]}'
                    f'  ·  {len(header["wrapped_key_digits"])} RSA blocks')
        return 'AES-256 key from X25519 + ML-KEM-768  ·  1,088-byte ML-KEM ciphertext'

    def _render_chat(self):
        chat = self.chats.get(self.current) if self.current else None
        self.chat_title.config(text=self.current or 'Pick someone on the left')
        session = chat['session'] if chat else None
        self.chat_lock.config(text=self._lock_text(session) if session else '')
        self.entry.config(state='normal' if session else 'disabled')
        self.log.config(state='normal')
        self.log.delete('1.0', 'end')
        for kind, who, text in chat['lines'] if chat else []:
            if kind == 'sys':
                self.log.insert('end', text + '\n', 'sys')
            else:
                self.log.insert('end', who + '\n', 'who_' + kind)
                self.log.insert('end', f' {text} \n', kind)
        self.log.config(state='disabled')
        self.log.see('end')
        if session:
            self.entry.focus_set()

    def _send(self):
        chat = self.chats.get(self.current)
        text = self.entry.get().strip()
        if not chat or not chat['session'] or not text:
            return
        try:
            chat['session'].send(text)
        except (OSError, ProtocolError) as error:
            chat['lines'].append(('sys', '', f'Not sent: {error}'))
        else:
            chat['lines'].append(('me', 'You', text))
            self.entry.delete(0, 'end')
        self._render_chat()

    # ---------- background events ----------
    def _pump(self):
        try:
            while True:
                event = self.events.get_nowait()
                getattr(self, '_on_' + event[0])(*event[1:])
        except queue.Empty:
            pass
        self.root.after(100, self._pump)

    def _on_session(self, session):
        chat = self._chat(session.peer)
        if chat['session'] is not None and chat['session'] is not session:
            chat['session'].close()
        chat['session'], chat['dialling'] = session, False
        chat['lines'].append(('sys', '', f'Secure chat started  ·  {self._lock_text(session)}'))
        if self.current is None:
            self.current = session.peer
        if self.current != session.peer:
            chat['unread'] += 1
        self._render_chat()
        self._render_peers()

    def _on_message(self, session, text):
        chat = self._chat(session.peer)
        chat['lines'].append(('them', session.peer, text))
        if self.current != session.peer:
            chat['unread'] += 1
        else:
            self._render_chat()
        self._render_peers()

    def _on_closed(self, session, error):
        chat = self.chats.get(session.peer)
        if chat and chat['session'] is session:
            chat['session'] = None
            chat['lines'].append(('sys', '', f'{session.peer} left the chat.' + (f' ({error})' if error else '')))
            if self.current == session.peer:
                self._render_chat()
            self._render_peers()

    def _on_dial_failed(self, name, error):
        chat = self._chat(name)
        chat['dialling'] = False
        chat['lines'].append(('sys', '', f'Could not connect: {error}'))
        if self.current == name:
            self._render_chat()

    def _on_notice(self, message):
        if self.current:
            self._chat(self.current)['lines'].append(('sys', '', message))
            self._render_chat()

    def quit(self):
        if self.identity is not None:
            self.registry.withdraw(self.identity)
        if self.node is not None:
            self.node.stop()
        for chat in self.chats.values():
            if chat['session']:
                chat['session'].close()
        self.root.destroy()


def main():
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    ChatApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
