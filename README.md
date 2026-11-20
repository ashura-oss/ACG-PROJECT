# ACG: Shor vs post-quantum

Chat messages are encrypted with AES-256. The AES key is locked with either:

- **RSA** (a random 7-bit key), which the Interceptor cracks live with a simulation of Shor's algorithm, or
- **post-quantum** X25519 + ML-KEM-768, which Shor's cannot crack.

## Install (Windows)

Install [Npcap](https://npcap.com/#download), then:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run

1. Start the Interceptor:

   ```powershell
   .\.venv\Scripts\pythonw.exe interceptor_app.py
   ```

2. Start two or more chatters. Give each a name and pick a lock:

   ```powershell
   .\.venv\Scripts\pythonw.exe chat_app.py
   ```

3. Click a name to chat. Chatters only see others with the same lock.
4. In the Interceptor, open the conversation's tab and press **Crack with Shor's**.

## Test

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```
