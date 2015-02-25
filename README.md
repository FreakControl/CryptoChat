# CryptoChat
NSA-Proof Secure P2P Chat client

NOTES:
  You may have port forwarded the desired chat port
  All communications are encrypted with XOR, AES, and base64
  To chat with someone make sure that they have your ip address and port you are using (get it from ipchicken.com).
  NEVER PUBLICLY POST YOUR IP! This could result in: Getting DDoSed, Doxed, being hacked, having the feds at your door, being killed, etc.
  Also make sure you are using the same keys as the person you are chatting with else it will not work.
  Always transfer the keys securely otherwise someone could eavesdrop on you and decrypt the conversation if they know what they are doing
  Always send the keys over a secure connection (SSL) since someone could be eavesdropping on your network and they could decrypt your conversation if they know what they are doing.
Commands:
  /send <file>:
    sends a file over the chat.
  /leave
    Closes chat client for both users chatting, ends session.
  /msg <ip>
    switch between different IPs while chatting (using the same keys)
  More to come soon.

This program is under the GPLv3 license.
