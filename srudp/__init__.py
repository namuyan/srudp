"""
`connection()` establishment process
====
```uml
                  ┌─┐                                            ┌─┐
                  │A│                                            │B│
                  └┬┘                                            └┬┘
                   │              udp-hole-punching               │
                   │────────────────────────────────────────────> │
                   │                                              │
                   │           udp-hole-punching (fail)           │
                   │ X<───────────────────────────────────────────│
                   │                                              │
                   │               send B's publicKey             │
                   │ <────────────────────────────────────────────│
                   │                                              │
                   │ send sharedKey (encrypted by sharedPoint)    │ ╔═══════════════╗
                   │───────────────────────────────────────────────>║ B established ║
                   │                                              │ ╚═══════════════╝
╔════════════════╗ │ send establish flag (encrypted by sharedKey) │
║ A established  ║<───────────────────────────────────────────────│
╚════════════════╝ │                                              │
                  ┌┴┐                                            ┌┴┐
                  │A│                                            │B│
                  └─┘                                            └─┘
```

note
----
* only one of two hole-punching is success in most case.
* when both hole-punching is success, use high priority side's sharedKey, but is rare case.
* when both hole-punching is fail, you can't use UDP-hole-punching method in your network.
* sharedPoint is calculated by multiply secretKey with publicKey.
* sharedKey is random 256bit bytes, don't use sharedPoint as sharedKey.
"""
from typing import NamedTuple, Optional, Union, Deque, Tuple, Callable, Any
from select import select
from time import sleep, time
from collections import deque
from hashlib import sha256
from binascii import a2b_hex
from Cryptodome.Cipher import AES
from Cryptodome.Cipher._mode_gcm import GcmMode
from struct import Struct
from socket import socket
import socket as s
import threading
import logging
import atexit
import ecdsa
import os


log = logging.getLogger(__name__)
packet_struct = Struct("<BIBd")

CONTROL_ACK = 0b00000001  # Acknowledge
CONTROL_PSH = 0b00000010  # Push data immediately
CONTROL_EOF = 0b00000100  # end of file
CONTROL_BCT = 0b00001000  # broadcast
CONTROL_RTM = 0b00010000  # ask retransmission
# CONTROL_MTU = 0b00100000  # fix MTU size
CONTROL_FIN = 0b01000000  # fin
FLAG_NAMES = {
    0b00000000: "---",
    CONTROL_ACK: "ACK",
    CONTROL_PSH: "PSH",
    CONTROL_EOF: "EOF",
    CONTROL_PSH | CONTROL_EOF: "PSH+EOF",
    CONTROL_BCT: "BCT",
    CONTROL_RTM: "RTM",
    # CONTROL_MTU: "MTU",
    CONTROL_FIN: "FIN",
}
WINDOW_MAX_SIZE = 32768  # 32kb
SEND_BUFFER_SIZE = WINDOW_MAX_SIZE * 8  # 256kb
MAX_RETRANSMIT_LIMIT = 4
FULL_SIZE_PACKET_WAIT = 0.001  # sec

# Path MTU Discovery
IP_MTU = 14
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0
IP_PMTUDISC_DO = 2

# connection stage
S_HOLE_PUNCHING = b'\x00'
S_SEND_PUBLIC_KEY = b'\x01'
S_SEND_SHARED_KEY = b'\x02'
S_ESTABLISHED = b'\x03'

# typing
_Address = Tuple[Any, ...]
_WildAddress = Union[_Address, str, bytes]
_BroadcastHook = Callable[['Packet', 'SecureReliableSocket'], None]


class CycInt(int):
    """
    cycle 4bytes unsigned integer
    loop 0 ~ 0xffffffff
    """
    def __add__(self, other: int) -> 'CycInt':
        return CycInt(super().__add__(other) % 0x100000000)

    def __sub__(self, other: int) -> 'CycInt':
        return CycInt(super().__sub__(other) % 0x100000000)

    def __hash__(self) -> int:
        return self % 0x100000000

    def __lt__(self, other: int) -> bool:
        """self<value"""
        i = int(self)
        other = int(other)
        if i < 0x3fffffff:
            if other < 0xbfffffff:
                return i < other
            else:
                return False
        elif i < 0xbfffffff:
            return i < other
        else:
            if other < 0x3fffffff:
                return True
            else:
                return i < other

    def __le__(self, other: int) -> bool:
        """self<=value"""
        if self == other:
            return True
        return self.__lt__(other)

    def __ge__(self, other: int) -> bool:
        """self>=value"""
        return not self.__lt__(other)

    def __gt__(self, other: int) -> bool:
        """self>value"""
        return not self.__le__(other)


# static cycle int
CYC_INT0 = CycInt(0)


class Packet(NamedTuple):
    """
    static 14b
    [control 1b]-[sequence(ack) 4b]-[retry 1b]-[time 8b]-[data xb]
    """
    control: int  # control bit
    sequence: CycInt  # packet order (cycle 4bytes uint)
    retry: int  # re-transmission count (disconnected before overflow)
    time: float  # unix time (double)
    data: bytes  # data body

    def __repr__(self) -> str:
        return "Packet({} seq:{} retry:{} time:{} data:{}b)".format(
            FLAG_NAMES.get(self.control), self.sequence,
            self.retry, round(self.time, 2), len(self.data))


def bin2packet(b: bytes) -> 'Packet':
    c, seq, r, t = packet_struct.unpack_from(b)
    return Packet(c, CycInt(seq), r, t, b[packet_struct.size:])


def packet2bin(p: Packet) -> bytes:
    # log.debug("s>> %s", p)
    return packet_struct.pack(p.control, int(p.sequence), p.retry, p.time) + p.data


def get_formal_address_format(address: _WildAddress, family: int = s.AF_INET) -> _Address:
    """tuple of ipv4/6 correct address format"""
    assert isinstance(address, tuple), "cannot recognize bytes or str format"
    for _, _, _, _, addr in s.getaddrinfo(str(address[0]), int(address[1]), family, s.SOCK_STREAM):
        return addr
    else:
        raise ConnectionError("not found correct ip format of {}".format(address))


class SecureReliableSocket(socket):
    __slots__ = [
        "timeout", "span", "address", "shared_key", "mtu_size",
        "sender_seq", "sender_buffer", "sender_signal", "sender_buffer_lock", "sender_socket_optional",
        "receiver_seq", "receiver_unread_size", "receiver_socket",
        "broadcast_hook_fnc", "loss", "try_connect", "established"]

    def __init__(self, family: int = s.AF_INET, timeout: float = 21.0, span: float = 3.0) -> None:
        """
        :param family: socket type AF_INET or AF_INET6
        :param timeout: auto socket close by the time passed (sec)
        :param span: check socket status by the span (sec)
        """
        # self bind buffer
        super().__init__(family, s.SOCK_STREAM)
        super().bind(("127.0.0.1" if family == s.AF_INET else "::1", 0))
        self_address = super().getsockname()
        super().connect(self_address)

        # inner params
        self.timeout = timeout
        self.span = span
        self.address: _Address = None
        self.shared_key: bytes = None
        self.mtu_size = 0  # 1472b

        # sender params
        self.sender_seq = CycInt(1)  # next send sequence
        self.sender_buffer: Deque[Packet] = deque()
        self.sender_signal = threading.Event()  # clear when buffer is empty
        self.sender_buffer_lock = threading.Lock()
        self.sender_socket_optional: Optional[socket] = None

        # receiver params
        self.receiver_seq = CycInt(1)  # next receive sequence
        self.receiver_unread_size = 0
        self.receiver_socket = socket(family, s.SOCK_DGRAM)

        # broadcast hook
        # note: don't block this method or backend thread will be broken
        self.broadcast_hook_fnc: Optional[_BroadcastHook] = None

        # status
        self.loss = 0
        self.try_connect = False
        self.established = False

    def __repr__(self) -> str:
        if self.is_closed:
            status = "CLOSED"
        elif self.established:
            status = "ESTABLISHED"
        elif self.try_connect:
            status = "FAILED"
        else:
            status = "UNKNOWN"
        return "<SecureReliableSocket %s %s send=%s recv=%s loss=%s>"\
               % (status, self.address, self.sender_seq, self.receiver_seq, self.loss)

    def bind(self, _address: _WildAddress) -> None:
        raise NotImplementedError("don't use bind() method")

    def connect(self, address: _WildAddress) -> None:
        """throw hole-punch msg, listen port and exchange keys"""
        assert not self.established, "already established"
        assert not self.is_closed, "already closed socket"
        assert not self.try_connect, "already try to connect"

        # start communication (only once you can try)
        self.try_connect = True

        # bind socket address
        conn_addr = list(get_formal_address_format(address, self.family))
        bind_addr = conn_addr.copy()

        if conn_addr[0] in ("127.0.0.1", "::1"):
            # local (for debug)
            another_port = conn_addr[1]
            if another_port % 2:
                another_port -= 1  # use 2n+1 if 2n is used
            else:
                another_port += 1  # use 2n if 2n+1 is used
            # another socket is on the same PC and can bind only one
            try:
                self.receiver_socket.bind(tuple(bind_addr))
                conn_addr[1] = another_port
            except OSError:
                # note: this raise OSError if already bind
                # unexpected: this raise OSError if CLOSE_WAIT state
                bind_addr[1] = another_port
                self.receiver_socket.bind(tuple(bind_addr))
            self.sender_socket_optional = socket(self.family, s.SOCK_DGRAM)
        else:
            # global
            bind_addr[0] = ""
            self.receiver_socket.bind(tuple(bind_addr))

        self.address = address = tuple(conn_addr)
        log.debug("try to communicate addr={} bind={}".format(address, bind_addr))

        # warning: allow only 256bit curve
        select_curve = ecdsa.curves.NIST256p
        log.debug("select curve {} (static)".format(select_curve))
        assert select_curve.baselen == 32, ("curve is 256bits size only", select_curve)

        # 1. UDP hole punching
        punch_msg = b"udp hole punching"
        self.sendto(S_HOLE_PUNCHING + punch_msg + select_curve.name.encode(), address)

        # my secret & public key
        my_sk = ecdsa.SigningKey.generate(select_curve)
        my_pk = my_sk.get_verifying_key()

        # other's public key
        other_pk: Optional[ecdsa.VerifyingKey] = None

        check_msg = b"success hand shake"
        for _ in range(int(self.timeout / self.span)):
            r, _w, _x = select([self.receiver_socket.fileno()], [], [], self.span)
            if r:
                data, _addr = self.receiver_socket.recvfrom(1024)
                stage, data = data[:1], data[1:]

                if stage == S_HOLE_PUNCHING:
                    # 2. send my public key
                    curve_name = data.replace(punch_msg, b'').decode()
                    other_curve = find_ecdhe_curve(curve_name)
                    assert select_curve == other_curve, ("different curve", select_curve, other_curve)
                    select_curve = find_ecdhe_curve(curve_name)
                    self.sendto(S_SEND_PUBLIC_KEY + my_pk.to_string(), address)
                    log.debug("success UDP hole punching")

                elif stage == S_SEND_PUBLIC_KEY:
                    # 3. get public key & send shared key
                    other_pk = ecdsa.VerifyingKey.from_string(data, select_curve)
                    shared_point = my_sk.privkey.secret_multiplier * other_pk.pubkey.point
                    self.shared_key = sha256(int(shared_point.x()).to_bytes(32, 'big')).digest()
                    shared_key = os.urandom(32)
                    encrypted_data = my_pk.to_string().hex() + "+" + self._encrypt(shared_key).hex()
                    self.shared_key = shared_key
                    self.sendto(S_SEND_SHARED_KEY + encrypted_data.encode(), address)
                    log.debug("success getting shared key")

                elif stage == S_SEND_SHARED_KEY:
                    # 4. decrypt shared key & send hello msg
                    encrypted_data = data.decode().split("+")
                    if other_pk is None:
                        other_pk = ecdsa.VerifyingKey.from_string(a2b_hex(encrypted_data[0]), select_curve)
                    else:
                        log.debug("need to check priority because already get others's pk")
                        my_pri = sha256(my_pk.to_string() + other_pk.to_string()).digest()
                        other_pri = sha256(other_pk.to_string() + my_pk.to_string()).digest()
                        # check 256bit int as big-endian
                        if my_pri < other_pri:
                            log.debug("my priority is LOW and over write my shared key by other's")
                        elif other_pri < my_pri:
                            log.debug("my priority is HIGH and ignore this command")
                            continue
                        else:
                            raise ConnectionError("my and other's key is same, this means you connect to yourself")
                    if my_sk is None:
                        raise ConnectionError("not found my_sk")
                    shared_point = my_sk.privkey.secret_multiplier * other_pk.pubkey.point
                    self.shared_key = sha256(int(shared_point.x()).to_bytes(32, 'big')).digest()
                    self.shared_key = self._decrypt(a2b_hex(encrypted_data[1]))
                    self.sendto(S_ESTABLISHED + self._encrypt(check_msg), address)
                    log.debug("success decrypt shared key")
                    break

                elif stage == S_ESTABLISHED:
                    # 5. check establish by decrypt specific message
                    decrypt_msg = self._decrypt(data)
                    if decrypt_msg != check_msg:
                        raise ConnectionError("failed to check")
                    log.debug("success hand shaking")
                    break

                else:
                    raise ConnectionError("not defined message received {}len".format(len(data)))
        else:
            # cannot establish
            raise ConnectionError("timeout on hand shaking")

        # get best MUT size
        # set don't-fragment flag & reset after
        # avoid Path MTU Discovery Blackhole
        if self.family == s.AF_INET:
            self.receiver_socket.setsockopt(s.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        self.mtu_size = self._find_mtu_size()
        if self.family == s.AF_INET:
            self.receiver_socket.setsockopt(s.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
        log.debug("success get MUT size %db", self.mtu_size)

        # success establish connection
        threading.Thread(target=self._backend, name="SRUDP", daemon=True).start()
        self.established = True

        # auto exit when program closed
        atexit.register(self.close)

    def _find_mtu_size(self) -> int:
        """confirm by submit real packet"""
        wait = 0.05
        mut = 1472  # max ipv4:1472b, ipv6:1452b
        receive_size = 0
        my_mut_size = None
        finished_notify = False
        for _ in range(int(self.timeout/wait)):
            r, _w, _x = select([self.receiver_socket.fileno()], [], [], wait)
            if r:
                data, _addr = self.receiver_socket.recvfrom(1500)
                if data.startswith(b'#####'):
                    if len(data) < receive_size:
                        self.sendto(receive_size.to_bytes(4, 'little'), self.address)
                        finished_notify = True
                    else:
                        receive_size = max(len(data), receive_size)
                elif len(data) == 4:
                    my_mut_size = int.from_bytes(data, 'little')
                else:
                    pass
            elif finished_notify and my_mut_size:
                return my_mut_size
            elif 1024 < mut:
                try:
                    if my_mut_size is None:
                        self.sendto(b'#' * mut, self.address)
                except s.error:
                    pass
                mut -= 16
            else:
                pass
        else:
            raise ConnectionError("timeout on finding MUT size")

    def _backend(self) -> None:
        """reorder sequence & fill output buffer"""
        temporary = dict()
        retransmit_packets: Deque[Packet] = deque()
        retransmitted: Deque[float] = deque(maxlen=16)
        last_packet: Optional[Packet] = None
        last_receive_time = time()
        last_ack_time = time()

        while not self.is_closed:
            r, _w, _x = select([self.receiver_socket.fileno()], [], [], self.span)

            # re-transmit
            if 0 < len(self.sender_buffer):
                with self.sender_buffer_lock:
                    now = time() - self.span * 2
                    transmit_limit = MAX_RETRANSMIT_LIMIT  # max transmit at once
                    for i, p in enumerate(self.sender_buffer):
                        if transmit_limit == 0:
                            break
                        if p.time < now:
                            self.loss += 1
                            re_packet = Packet(p.control, p.sequence, p.retry+1, time(), p.data)
                            self.sender_buffer[i] = re_packet
                            self.sendto(self._encrypt(packet2bin(re_packet)), self.address)
                            transmit_limit -= 1

            # send ack as ping (stream may be free)
            if self.span < time() - last_ack_time:
                p = Packet(CONTROL_ACK, self.receiver_seq - 1, 0, time(), b'as ping')
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                last_ack_time = time()

            # connection may be broken
            if self.timeout < time() - last_receive_time:
                p = Packet(CONTROL_FIN, CYC_INT0, 0, time(), b'stream may be broken')
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                break

            # just socket select timeout (no data received yet)
            if len(r) == 0:
                continue

            """received a packet data"""

            try:
                data, _addr = self.receiver_socket.recvfrom(65536)
                packet = bin2packet(self._decrypt(data))

                last_receive_time = time()
                # log.debug("r<< %s", packet)
            except ValueError:
                # log.debug("decrypt failed len=%s..".format(data[:10]))
                continue
            except (ConnectionResetError, OSError):
                break
            except Exception:
                log.error("UDP socket closed", exc_info=True)
                break

            # receive ack
            if packet.control & CONTROL_ACK:
                with self.sender_buffer_lock:
                    if 0 < len(self.sender_buffer):
                        for i in range(packet.sequence - self.sender_buffer[0].sequence + 1):
                            # remove packet that sent and confirmed by ACK
                            self.sender_buffer.popleft()
                            if len(self.sender_buffer) == 0:
                                break
                        if not self._send_buffer_is_full():
                            self.sender_signal.set()
                            log.debug("allow sending operation again seq={}".format(packet.sequence))
                continue

            # receive reset
            if packet.control & CONTROL_FIN:
                p = Packet(CONTROL_FIN, CYC_INT0, 0, time(), b'be notified fin or reset')
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                break

            # asked re-transmission
            if packet.control & CONTROL_RTM:
                with self.sender_buffer_lock:
                    for i, p in enumerate(self.sender_buffer):
                        if p.sequence == packet.sequence:
                            re_packet = Packet(p.control, p.sequence, p.retry+1, time(), p.data)
                            self.sender_buffer[i] = re_packet
                            self.sendto(self._encrypt(packet2bin(re_packet)), self.address)
                            retransmitted.append(packet.time)
                            break
                continue

            # broadcast packet
            if packet.control & CONTROL_BCT:
                if self.broadcast_hook_fnc is not None:
                    self.broadcast_hook_fnc(packet, self)
                elif last_packet is None or last_packet.control & CONTROL_EOF:
                    self._push_receive_buffer(packet.data)
                else:
                    # note: acquire realtime response
                    log.debug("throw away %s", packet)
                continue

            """normal packet from here (except PSH, EOF)"""

            # check the packet is retransmitted
            if 0 < packet.retry and 0 < len(retransmit_packets):
                limit = time() - self.span
                for i, p in enumerate(retransmit_packets):
                    if p.sequence == packet.sequence:
                        del retransmit_packets[i]
                        break  # success retransmitted
                    if p.sequence < self.receiver_seq:
                        del retransmit_packets[i]
                        break  # already received
                for i, p in enumerate(retransmit_packets):
                    # too old retransmission request
                    if p.time < limit:
                        re_packet = Packet(CONTROL_RTM, p.sequence, p.retry+1, time(), b'')
                        retransmit_packets[i] = re_packet
                        self.sendto(self._encrypt(packet2bin(re_packet)), self.address)
                        self.loss += 1
                        break

            # receive data
            if packet.sequence == self.receiver_seq:
                self.receiver_seq += 1
                self._push_receive_buffer(packet.data)
            elif packet.sequence > self.receiver_seq:
                temporary[packet.sequence] = packet
                # ask re-transmission if not found before packet
                lost_sequence = packet.sequence - 1
                if lost_sequence not in temporary:
                    for p in retransmit_packets:
                        if p.sequence == lost_sequence:
                            break  # already pushed request
                    else:
                        re_packet = Packet(CONTROL_RTM, lost_sequence, 0, time(), b'')
                        self.sendto(self._encrypt(packet2bin(re_packet)), self.address)
                        self.loss += 1
                        retransmit_packets.append(re_packet)
                else:
                    pass  # do not do anything..
            else:
                pass  # ignore old packet

            # request all lost packets when PSH (end of chunk)
            if (packet.control & CONTROL_PSH) and 0 < len(retransmit_packets):
                if 0 < len(retransmit_packets):
                    for i, p in enumerate(retransmit_packets):
                        if time() - p.time < self.span:
                            continue  # too early to RTM
                        re_packet = Packet(CONTROL_RTM, p.sequence, p.retry+1, time(), b'')
                        retransmit_packets[i] = re_packet
                        self.sendto(self._encrypt(packet2bin(re_packet)), self.address)
                        self.loss += 1

            # fix packet order & push buffer
            if self.receiver_seq in temporary:
                for sequence in sorted(temporary):
                    if sequence == self.receiver_seq:
                        self.receiver_seq += 1
                        packet = temporary.pop(sequence)  # warning: over write packet
                        self._push_receive_buffer(packet.data)

            # push buffer immediately
            if packet.control & CONTROL_PSH:
                # send ack
                p = Packet(CONTROL_ACK, self.receiver_seq - 1, 0, time(), b'put buffer')
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                last_ack_time = time()
                # log.debug("pushed! buffer %d %s", len(retransmit_packets), retransmit_packets)

            # reached EOF & push broadcast packets
            if packet.control & CONTROL_EOF:
                # note: stopped sending broadcast packet after main stream for realtime
                log.debug("reached end of chunk seq={}".format(packet.sequence))

            # update last packet
            last_packet = packet

        # close
        log.debug("srudp socket is closing now")
        self.close()

    def _push_receive_buffer(self, data: bytes) -> None:
        """just append new data to buffer"""
        if self.fileno() == -1:
            return  # already closed
        super().sendall(data)
        self.receiver_unread_size += len(data)

    def _send_buffer_is_full(self) -> bool:
        return SEND_BUFFER_SIZE < sum(len(p.data) for p in self.sender_buffer)

    def get_window_size(self) -> int:
        """maximum size of data you can send at once"""
        # Packet = [nonce 16b][tag 16b][static 14b][data xb]
        return self.mtu_size - 32 - packet_struct.size

    def send(self, data: bytes, flags: int = 0) -> int:
        """over write low-level method for compatibility"""
        assert flags == 0, "unrecognized flags"
        self.sendall(data)
        return len(data)

    def _send(self, data: memoryview) -> int:
        """warning: row-level method"""
        if not self.established:
            raise ConnectionAbortedError('disconnected')

        window_size = self.get_window_size()
        length = len(data) // window_size
        send_size = 0
        for i in range(length + 1):
            # control flag
            control = 0b00000000
            buffer_is_full = self._send_buffer_is_full()
            if i == length or buffer_is_full:
                control |= CONTROL_PSH
            if i == length:
                control |= CONTROL_EOF

            # send one packet
            throw = data[window_size * i:window_size * (i + 1)]
            with self.sender_buffer_lock:
                packet = Packet(control, self.sender_seq, 0, time(), throw.tobytes())
                self.sender_buffer.append(packet)
                self.sendto(self._encrypt(packet2bin(packet)), self.address)
                self.sender_seq += 1
            send_size += len(throw)

            # note: sleep a mSec to avoid packet loss
            if window_size == len(throw):
                sleep(FULL_SIZE_PACKET_WAIT)

            # block sendall() when buffer is full
            if buffer_is_full:
                self.sender_signal.clear()
                log.debug("buffer is full and wait for signaled")
                break
        return send_size

    def sendto(self, data: bytes, address: _Address) -> int:  # type: ignore
        """note: sendto() after bind() with different port cause OSError on recvfrom()"""
        if self.is_closed:
            return 0
        elif self.sender_socket_optional is None:
            return self.receiver_socket.sendto(data, address)
        else:
            return self.sender_socket_optional.sendto(data, address)

    def sendall(self, data: bytes, flags: int = 0) -> None:
        """high-level method, use this instead of send()"""
        assert flags == 0, "unrecognized flags"
        send_size = 0
        data = memoryview(data)
        while send_size < len(data):
            if not self._send_buffer_is_full():
                self.sender_signal.set()
            if self.sender_signal.wait(self.timeout):
                send_size += self._send(data[send_size:])
            else:
                log.debug("waiting for sending buffer have space..")
        log.debug("send operation success %sb", send_size)

    def broadcast(self, data: bytes) -> None:
        """broadcast data (do not check reach)"""
        if not self.established:
            raise ConnectionAbortedError('disconnected')
        # do not check size
        # window_size = self.get_window_size()
        # if window_size < len(data):
        #    raise ValueError("data is too big {}<{}".format(window_size, len(data)))
        packet = Packet(CONTROL_BCT, CYC_INT0, 0, time(), data)
        with self.sender_buffer_lock:
            self.sendto(self._encrypt(packet2bin(packet)), self.address)

    def recv(self, buflen: int = 1024, flags: int = 0) -> bytes:
        assert flags == 0, "unrecognized flags"

        if self.is_closed:
            return b""
        elif not self.established:
            return b""
        else:
            try:
                data = super().recv(buflen, flags)
                self.receiver_unread_size -= len(data)
                return data
            except ConnectionError:
                # self.close() called and buffer closed
                return b""

    def _encrypt(self, data: bytes) -> bytes:
        """encrypt by AES-GCM (more secure than CBC mode)"""
        cipher: 'GcmMode' = AES.new(self.shared_key, AES.MODE_GCM)  # type: ignore
        # warning: Don't reuse nonce
        enc, tag = cipher.encrypt_and_digest(data)
        # output length = 16bytes + 16bytes + N(=data)bytes
        return cipher.nonce + tag + enc

    def _decrypt(self, data: bytes) -> bytes:
        """decrypt by AES-GCM (more secure than CBC mode)"""
        cipher: 'GcmMode' = AES.new(self.shared_key, AES.MODE_GCM, nonce=data[:16])  # type: ignore
        # ValueError raised when verify failed
        return cipher.decrypt_and_verify(data[32:], data[16:32])

    def getsockname(self) -> _Address:
        """self bind info or raise OSError"""
        if self.is_closed:
            raise OSError("socket is closed")
        else:
            return self.receiver_socket.getsockname()  # type: ignore

    def getpeername(self) -> _Address:
        """connection info or raise OSError"""
        if self.is_closed:
            raise OSError("socket is closed")
        elif self.address is None:
            raise OSError("not found peer connection")
        else:
            return self.address

    @property
    def is_closed(self) -> bool:
        if self.receiver_socket.fileno() == -1:
            self.established = False
            atexit.unregister(self.close)
            return True
        return False

    def close(self) -> None:
        if self.established:
            self.established = False
            p = Packet(CONTROL_FIN, CYC_INT0, 0, time(), b'closed')
            self.sendto(self._encrypt(packet2bin(p)), self.address)
            self.receiver_socket.close()
            super().close()
            if self.sender_socket_optional is not None:
                self.sender_socket_optional.close()
            atexit.unregister(self.close)


def find_ecdhe_curve(curve_name: str) -> ecdsa.curves.Curve:
    for curve in ecdsa.curves.curves:
        if curve.name == curve_name:
            return curve
    else:
        raise ConnectionError("unknown curve {}".format(curve_name))


def get_mtu_linux(family: int, host: str) -> int:
    """MTU on Linux"""
    with socket(family, s.SOCK_DGRAM) as sock:
        sock.connect((host, 0))
        if family == s.AF_INET:
            # set option DF (only for ipv4)
            sock.setsockopt(s.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        return sock.getsockopt(s.IPPROTO_IP, IP_MTU)


def main() -> None:
    """for test"""
    import sys
    import random

    remote_host = sys.argv[1]
    port = int(sys.argv[2])
    msglen = int(sys.argv[3])

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '[%(levelname)-6s] [%(threadName)-10s] [%(asctime)-24s] %(message)s')
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    sock = SecureReliableSocket()
    sock.connect((remote_host, port))
    log.debug("connect success! mtu=%d", sock.mtu_size)

    def listen() -> None:
        size, start = 0, time()
        while True:
            r = sock.recv(8192)
            if len(r) == 0:
                break
            if 0 <= r.find(b'start!'):
                size, start = 0, time()
            size += len(r)
            if 0 <= r.find(b'success!'):
                span = max(0.000001, time()-start)
                log.debug("received! %db loss=%d %skb/s\n", size, sock.loss, round(size/span/1000, 2))
            # log.debug("recv %d %d", size, len(r))
        log.debug("closed receive")

    def sending() -> None:
        while msglen:
            sock.sendall(b'start!'+os.urandom(msglen)+b'success!')  # +14
            log.debug("send now! loss=%d time=%d", sock.loss, int(time()))
            if 0 == random.randint(0, 5):
                sock.broadcast(b'find me! ' + str(time()).encode())
                log.debug("send broadcast!")
            sleep(20)

    def broadcast_hook(packet: Packet, _sock: SecureReliableSocket) -> None:
        log.debug("find you!!! (%s)", packet)

    sock.broadcast_hook_fnc = broadcast_hook
    threading.Thread(target=listen).start()
    threading.Thread(target=sending).start()


if __name__ == '__main__':
    main()


__all__ = [
    "Packet",
    "bin2packet",
    "packet2bin",
    "get_formal_address_format",
    "SecureReliableSocket",
    "get_mtu_linux",
]
