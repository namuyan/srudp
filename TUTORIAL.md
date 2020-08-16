tutorial for users "cannot work on my condition"
====
How to use this library on two VPSs.

purpose
----
I have designed this library that nobody worry about the there environment,
no dependency on OS and written by pure-Python.
However, some users submit report of dependence problem in unexpected condition.
As far as I checked, it goes from network security policy to network adapter and etc.
So, I wrote this tutorial that works in a universal environment by VPSs.

about VPS
----
Choose two complete independent VPS providers and choose the cheapest plan.
I would recommend [vulter](ttps://www.vultr.com/?ref=7215429) and
[time4vps](ttps://www.time4vps.com/?affid=5018).
Especially you can rent an hour on **vulter** by a few cents.
If you already have a server, you can use it to save money, but
you should be responsible because you need to set up a firewall,
please be careful about mistakes.

rent VPS
----
You should check
* Ubuntu (you can select other dist and windows but.. no guarantee)
* Python3.6 or newer (default installed maybe but check)
* PIP (default installed maybe but check)
* protected by ufw (default deny)

prepare
----
1. install `pip3 install --user git+https://github.com/namuyan/srudp`

2. check ip by `ip addr show`
```shell script
vps@store:~$ ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: venet0: <BROADCAST,POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN 
    link/void 
    inet 127.0.0.2/32 scope host venet0
    inet 11.22.33.44/32 brd 11.22.33.44 scope global venet0:0
    inet6 2a14:a311:aa80:63cf::1/128 scope global 
       valid_lft forever preferred_lft forever
```
find ipv4 `11.22.33.44` and another side is `55.66.77.88`.

setup one side
----
open repl.
````shell script
[p2p@vps ~]$ python3
Python 3.7.2 (default, Mar  9 2019, 23:55:13) 
[GCC 4.8.5 20150623 (Red Hat 4.8.5-36)] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from srudp import *
>>> sock = SecureReliableSocket()
>>> sock.connect(("11.22.33.44", 10020))  # don't type, wait!
````

setup another side
----
```shell script
Python 3.6.2 (default, Jul 20 2017, 08:43:29) 
[GCC 5.4.1 20170519] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from srudp import *
>>> sock = SecureReliableSocket()
>>> sock.connect(("55.66.77.88", 10020))  # don't type, wait again!
```

establish connection
----
**Let's type** on two console by manual, don't need to be care about timing.
This work to be executed in half a minutes, I think.

Nothing return? you may be success!

If raised error like below, hole-punch-message don't reach.
```text
ConnectionError: timeout on hand shaking
```

send message and receive it
----
socket do auto ping-pong to maintain connection.
You can see the work by logging on by debug level, but noisy.

Let's send message *"hello world?"*
````shell script
>>> sock.sendall(b"hello world?")
>>>
````

And get the message by another side.
```shell script
>>> sock.recv(1024)
b'hello world?'
>>> 
```

advance stage 1, let's send big data
----
generate random 16Mb binary and send.
```shell script
>>> import os
>>> from hashlib import sha256
>>> data = os.urandom(1024*1024*16)
>>> len(data)
16777216
>>> sha256(data).hexdigest()
'f6232284969ef76ad4baccd7d808eeb3a05686e0320a8661bddfd549c949a708'
>>> sock.sendall(data)
```

receive the data and check sha256.
```shell script
>>> from hashlib import sha256
>>> sock.settimeout(30.0)
>>> data = b''
>>> while True:
        try:
...         data += sock.recv(8192)
...     except Exception as e:
...         print("timeout", e)
...         break
...
socket.timeout
>>> len(data)
16777216
>>> sha256(data).hexdigest()
'f6232284969ef76ad4baccd7d808eeb3a05686e0320a8661bddfd549c949a708'
```
You can send big data like TCP easily.

You may loss same packets when big data sending,
you can know your internet stability by `sock.loss`.
```shell script
>>> sock.loss / sock.receiver_seq * 100
0.151597273548493
```
I just transmitted from home PC at Japan to VPS hosted on Slovakia.
This too long distance make me lost 0.15% of all packet.

advance stage 2, unreliable broadcast
----
You can send message like UDP, but you can't detect the data reached.
It's good for P2P mesh network broadcasting, I think.

Just broadcast short message.
````shell script
>>> sock.broadcast(b"why?")
````

And receive it.
```shell script
>>> sock.recv(1024)
b'why?'
```

You can also hook the message like this.
normal `sock.sendall` message go `sock.recv`, only broadcast message.
You will have big latency when don't hook broadcast
because normal data stream block broadcast to avoid confuse data.
```shell script
>>> sock.broadcast_hook_fnc = lambda (p, s): print(p, ",", p.data)
Packet(BCT seq:0 retry:0 time:1591543763.87 data:4b) , b'why?'
```

close socket
----
close by `sock.close()` or **ctrl+C**.
socket send close signal to other side.

Let's see socket status
```shell script
>>> sock
<srudp.SecureReliableSocket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_DGRAM, proto=0>
>>>
```

questions
----
1. You may have question "Which is server and client side?",
the answer is "You don't need to worry about the features".
**SRUDP** just send and receive UDP packet with only one side.
It is true that the role is divided only in connection,
but it is divided internally according to whether a punching message is "received"
or "not received" by network communication delay.

2. And you may have question "how to justify connection timing?",
the answer is "You need to setup **signaling server**".
I leave a implementation of this to the users, please.

recommend other challenge
----
* connect your home and VPS or your friend
* windows and Linux
* Ipv6 connection
* implement signaling system
