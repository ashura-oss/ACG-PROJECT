# Passive quantum chat implementation

Build a two-way terminal chat between two processes communicating directly over
TCP. A third process passively captures their traffic and recovers session secrets
through the existing RSA-33 Shor simulation. Preserve the original local demo.

## Stages

1. Add a bounded, versioned protocol and independent chat peers. Use fresh session
   secrets, direction-separated HKDF keys, AES-256-GCM, authenticated sequence
   numbers, and strictly validated frames.
2. Add passive loopback/interface capture and saved-PCAP import. Reassemble TCP
   streams, including segmentation, retransmissions and out-of-order delivery.
   Capture only the configured chat port; no relay or endpoint key-file access.
3. Add a persistent captured-message queue and quantum-derived key recovery.
   Capture continues while simulation runs. Recover once per RSA public key;
   decrypt each session independently and authenticate before displaying text.
4. Verify real bidirectional sockets, packet import, fresh-process Shor recovery,
   queued sessions, tampering, missing data, duplicate packets and failures. Add
   three-terminal instructions and document platform capture prerequisites.

## Acceptance and boundaries

- Alice and Bob continue communicating if the observer exits.
- The observer reads captured public traffic, not peer secrets or plaintext logs.
- Quantum recovery uses actual Aer measurement evidence and no classical fallback.
- Failure leaves ciphertext queued and never produces fabricated recovered text.
- Live capture on Windows requires Npcap loopback support and appropriate access.
  Offline fixture tests do not establish that a live capture driver works.
- RSA-33 remains deliberately insecure. This demonstrates the attack mechanism,
  not quantum speed advantage or a production RSA/TLS break.
- Work is committed incrementally on `codex/quantum-passive-chat`.
