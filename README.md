# ACG: Shor vs post-quantum

Alice and Bob chat with AES-256. The AES key is locked with either:

- **RSA**: a tiny random key that the Interceptor cracks live with a simulation of Shor's algorithm, or
- **PQC**: ML-KEM-768, which Shor's cannot crack.

The Interceptor sniffs the traffic and holds the encrypted messages. Once it cracks the key, it decrypts everything it held and then every new message live.

## Install (Windows)

Install [Npcap](https://npcap.com/#download), then:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run

```powershell
.\.venv\Scripts\pythonw.exe demo.py
```

This opens Alice, Bob and the Interceptor together.

1. Chat between Alice and Bob. The Interceptor holds the messages, still encrypted.
2. Press **Crack with Shor's**. The held messages decrypt, and new ones decrypt live.
3. Press **PQC** in Alice's window to start a post-quantum chat. Cracking it fails.

## Files

| File | Contents |
|---|---|
| `demo.py` | The three windows |
| `common.py` | AES and the two locks |
| `shor.py` | Shor's algorithm (`python shor.py 91` factors 91) |
