Secure Reliable UDP
====
This repository provides **Secure Reliable Data Stream** that works like TCP.  
My purpose is enable users create P2P connection between clients in closed NAT.

Features
----
* Pure Python
* Usage like normal socket object
* Protocol similar to RUDP
* UDP hole punching
* high performance (4Mbps/s Up&Down when 10mb)
* ipv4/ipv6

Requirement
----
* Python**3.6+**
* [requirements.txt](requirements.txt)

Installation
----
[tutorial for users "cannot work on my condition"](TUTORIAL.md)
```bash
pip3 install --user srudp
```

Demo
----
Prepare two independent PCs.
```python
from srudp import SecureReliableSocket
from time import sleep, time
 
sock = SecureReliableSocket()
sock.connect(("<remote host 1>", 12345))
 
while not sock.is_closed:
    sock.sendall(b'hello ' + str(time()).encode())
    sleep(3)
print("closed", sock)
```
A side, send message hello once in a 3 sec.

```python
from srudp import SecureReliableSocket
from time import time
 
sock = SecureReliableSocket()
sock.connect(("<remote host 2>", 12345))
 
while not sock.is_closed:
    data = sock.recv(1024)
    if not data:
        break
    print(time(), data)
print("closed", sock)
```
Another side, receive the message and show immediately.

to avoid troubles
----
* Do not think **always success connection  establish**.
Web-RTC detect UDP-hole-punching success, or use alternative way when failed, you need to implement it.
* UDP (and some TCP) is often **blocked** on public network
like airport free wifi and university local LAN etc.
Addition to it, some router and network adapter sometimes block.
* I designed this **simple TCP like socket object**.
This don't have signaling function, haven't data specialized because
I will use this as one of low-layer libraries for P2P.

Note: Why make this?
----
These days, PC is located in a local environment protected by NAT.
It is difficult to transfer data between two outsides.
In order to solve this problem, connection is realized by **UDP hole punching**
without using UPnP.

UDP is a socket protocol with minimum functions for connecting applications.
Therefore, there is no connection state, data may not be reachable,
spoofing the source is easy. This is why, you cannot substitute it as TCP.

With this program, you can treat it just like TCP without worrying about the above problems.
In other words, it has a connection state, guarantees data reachability, and is difficult to forge.

Links
----
* [Winny -Port0 setting-](http://winny.4th.jp/lesson1/port.html)
* [lean about WebRTC](https://qiita.com/mush/items/121e45fefed009b6ad5e)
* [(24days) NAT Traversal](https://tech-blog.cerevo.com/adventcalendar2016/advent24/)
* [Peer-to-Peer Communication Across Network Address Translators](https://bford.info/pub/net/p2pnat/)

Author
----
[@namuyan](https://twitter.com/namuyan_mine)

Licence
----
MIT
