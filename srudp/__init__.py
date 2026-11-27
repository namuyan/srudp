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
from typing import TYPE_CHECKING, NamedTuple, Optional, Union, Deque, Tuple, Dict, List, Iterable, Callable, Any
from select import select
from time import sleep, time, perf_counter as clock
from collections import deque, OrderedDict
from hashlib import sha256
from binascii import a2b_hex
from Cryptodome.Cipher import ChaCha20_Poly1305
from struct import Struct, error as StructError
from socket import socket
import socket as s
import threading
import logging
import atexit
import ecdsa
import errno
import sys
import os


log = logging.getLogger(__name__)
packet_struct = Struct("<BIBd")
ack_struct = Struct("<dB")  # ACK body: [echo time 8b][number of SACK blocks 1b]
sack_struct = Struct("<II")  # SACK block: [first seq 4b][last seq 4b] (both inclusive)

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
SEND_BUFFER_SIZE = 4 * 1024 * 1024  # 4mb, max data size waiting for ACK
MAX_TEMPORARY_PACKET_SIZE = 50000
RECEIVE_BATCH_SIZE = 128  # max datagrams read at once before acknowledging
ACK_EVERY = 32  # acknowledge at least every N in-order packets (and at the end of each batch)
MAX_SACK_BLOCKS = 32  # max SACK blocks in one ACK
MIN_REORDER_WINDOW = 0.001  # sec, packet sent this earlier than a delivered one is lost

# retransmission timeout (RFC 6298)
INITIAL_RTO = 1.0  # sec
MIN_RTO = 0.2  # sec (same as Linux)
MAX_RTO = 60.0  # sec
MAX_RTO_BACKOFF = 64
MIN_PTO = 0.01  # sec, tail loss probe timeout = max(2*SRTT, MIN_PTO)
IDLE_SELECT_TIMEOUT = 0.05  # sec, backend wakes up to start timers for data sent while idle

# congestion control (cwnd is counted by packets)
INITIAL_CWND = 10.0
MIN_CWND = 2.0
MAX_CWND = float(SEND_BUFFER_SIZE // 1024)
CWND_BETA = 0.7  # multiplicative decrease factor on loss
# HyStart: leave slow start when queueing delay grows (avoid filling buffers until loss)
HYSTART_MIN_DELAY = 0.004  # sec
HYSTART_MAX_DELAY = 0.016  # sec

# pacing: spread packets over RTT instead of bursting cwnd at once
PACING_GAIN_SLOW_START = 2.0
PACING_GAIN = 1.25
PACING_BURST_TIME = 0.002  # sec, allowed burst (absorb coarse sleep() resolution)
PACING_MIN_BURST = 16 * 1024  # bytes

# OS socket buffer, absorb bursts while the backend thread is busy (decrypting etc.)
SOCKET_BUFFER_SIZE = 1024 * 1024  # 1mb (OS may limit it smaller)

# Path MTU Discovery
IP_MTU = 14
IP_MTU_DISCOVER = 10  # Linux
IP_PMTUDISC_DONT = 0
IP_PMTUDISC_DO = 2
IP_DONTFRAG = 28  # macOS (11+)
IP_DONTFRAGMENT = 14  # Windows

# encryption: [nonce 24b][tag 16b][encrypted data]
NONCE_SIZE = 24  # XChaCha20-Poly1305
TAG_SIZE = 16
CIPHER_OVERHEAD = NONCE_SIZE + TAG_SIZE

# connection stage
S_HOLE_PUNCHING = b'\x00'
S_SEND_PUBLIC_KEY = b'\x01'
S_SEND_SHARED_KEY = b'\x02'
S_ESTABLISHED = b'\x03'

# typing
if TYPE_CHECKING:
    from _typeshed import ReadableBuffer
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


class RttEstimator(object):
    """
    smoothed RTT & retransmission timeout (RFC 6298)
    samples are measured by echoed timestamp, so retransmitted packets are fine (no Karn's problem)
    """
    __slots__ = ["srtt", "rttvar", "min_rtt", "latest", "backoff"]

    def __init__(self) -> None:
        self.srtt: Optional[float] = None
        self.rttvar = 0.0
        self.min_rtt = float("inf")
        self.latest = 0.0
        self.backoff = 1

    def update(self, sample: float) -> None:
        if sample <= 0.0:
            return
        self.latest = sample
        self.min_rtt = min(self.min_rtt, sample)
        if self.srtt is None:
            self.srtt = sample
            self.rttvar = sample / 2.0
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
            self.srtt = 0.875 * self.srtt + 0.125 * sample
        self.backoff = 1

    def on_timeout(self) -> None:
        self.backoff = min(self.backoff * 2, MAX_RTO_BACKOFF)

    @property
    def pto(self) -> float:
        """probe timeout for tail loss probe"""
        if self.srtt is None:
            return self.rto
        return min(self.rto, max(MIN_PTO, 2.0 * self.srtt))

    @property
    def rto(self) -> float:
        if self.srtt is None:
            base = INITIAL_RTO
        else:
            base = self.srtt + max(0.001, 4.0 * self.rttvar)
        return min(MAX_RTO, max(MIN_RTO, base) * self.backoff)


class CongestionControl(object):
    """
    loss based AIMD congestion control (NewReno style slow start & congestion avoidance)
    cwnd: max packets in flight (not ACKed & not SACKed & not lost)
    """
    __slots__ = ["cwnd", "ssthresh", "recovery_point"]

    def __init__(self) -> None:
        self.cwnd = INITIAL_CWND
        self.ssthresh = float("inf")
        self.recovery_point: Optional[CycInt] = None  # no more decrease for losses before this seq

    @property
    def in_slow_start(self) -> bool:
        return self.cwnd < self.ssthresh

    def on_ack(self, delivered: int, rtt: 'RttEstimator') -> None:
        if self.in_slow_start:
            # delay increase: queue is building up, cwnd is enough
            threshold = min(HYSTART_MAX_DELAY, max(HYSTART_MIN_DELAY, rtt.min_rtt / 8.0))
            if 32.0 <= self.cwnd and rtt.min_rtt + threshold < rtt.latest:
                self.ssthresh = self.cwnd
                return
            self.cwnd += delivered
        else:
            self.cwnd += delivered / self.cwnd
        self.cwnd = min(self.cwnd, MAX_CWND)

    def on_loss(self, lost_seq: CycInt, next_seq: CycInt) -> None:
        """decrease once per round trip (loss event)"""
        if self.recovery_point is not None and lost_seq < self.recovery_point:
            return  # same loss event
        self.ssthresh = max(self.cwnd * CWND_BETA, MIN_CWND)
        self.cwnd = self.ssthresh
        self.recovery_point = next_seq

    def on_timeout(self, next_seq: CycInt) -> None:
        self.ssthresh = max(self.cwnd * CWND_BETA, MIN_CWND)
        self.cwnd = 1.0
        self.recovery_point = next_seq


class Pacer(object):
    """token bucket to pace sending rate (rate 0.0 means no pacing)"""
    __slots__ = ["rate", "tokens", "last"]

    def __init__(self) -> None:
        self.rate = 0.0  # bytes/sec
        self.tokens = 0.0
        self.last = clock()

    def update(self, cwnd: float, srtt: Optional[float], packet_size: int, slow_start: bool) -> None:
        if srtt is None or srtt <= 0.0:
            self.rate = 0.0
        else:
            gain = PACING_GAIN_SLOW_START if slow_start else PACING_GAIN
            self.rate = gain * cwnd * packet_size / srtt

    def delay(self, size: int) -> float:
        """time to wait before sending `size` bytes (consume tokens when 0.0)"""
        rate = self.rate
        if rate <= 0.0:
            return 0.0
        now = clock()
        burst = max(PACING_MIN_BURST, rate * PACING_BURST_TIME)
        self.tokens = min(burst, self.tokens + (now - self.last) * rate)
        self.last = now
        if size <= self.tokens:
            self.tokens -= size
            return 0.0
        return (size - self.tokens) / rate


def ack_body(echo_time: float, blocks: 'List[Tuple[int, int]]') -> bytes:
    """
    [echo time 8b][number of blocks 1b]([first seq 4b][last seq 4b])*n
    echo time: time field of the packet triggered this ACK (0.0 is no RTT sample)
    blocks: received sequence ranges above cumulative ACK (selective ACK)
    """
    return ack_struct.pack(echo_time, len(blocks)) + b"".join(sack_struct.pack(a, b) for a, b in blocks)


def parse_ack_body(data: bytes) -> 'Tuple[float, List[Tuple[int, int]]]':
    if len(data) < ack_struct.size:
        return 0.0, []
    echo_time, number = ack_struct.unpack_from(data)
    blocks: 'List[Tuple[int, int]]' = list()
    for i in range(number):
        offset = ack_struct.size + i * sack_struct.size
        if len(data) < offset + sack_struct.size:
            break
        first, last = sack_struct.unpack_from(data, offset)
        blocks.append((first, last))
    return float(echo_time), blocks


def sack_blocks(base: int, received: 'Iterable[int]', limit: int = MAX_SACK_BLOCKS) -> 'List[Tuple[int, int]]':
    """continuous ranges of received sequences above `base` (cycle aware), nearest first"""
    offsets = sorted((int(seq) - base) % 0x100000000 for seq in received)
    blocks: 'List[Tuple[int, int]]' = list()
    start = prev = -2
    for offset in offsets:
        if offset == prev + 1:
            prev = offset
            continue
        if 0 <= start:
            blocks.append(((base + start) % 0x100000000, (base + prev) % 0x100000000))
            if limit <= len(blocks):
                return blocks
        start = prev = offset
    if 0 <= start:
        blocks.append(((base + start) % 0x100000000, (base + prev) % 0x100000000))
    return blocks


class _Segment(object):
    """sent packet waiting for ACK"""
    __slots__ = ["control", "sequence", "data", "xmit_time", "retry", "sacked", "lost"]

    def __init__(self, control: int, sequence: CycInt, data: bytes, xmit_time: float) -> None:
        self.control = control
        self.sequence = sequence
        self.data = data
        self.xmit_time = xmit_time  # last (re)transmission time
        self.retry = 0
        self.sacked = False  # received by peer (selective ACK)
        self.lost = False  # marked lost & waiting for retransmission

    def to_packet(self) -> 'Packet':
        return Packet(self.control, self.sequence, self.retry, self.xmit_time, self.data)


class Packet(NamedTuple):
    """
    static 14b
    [control 1b]-[sequence(ack) 4b]-[retry 1b]-[time 8b]-[data xb]
    """
    control: int  # control bit
    sequence: CycInt  # packet order (cycle 4bytes uint)
    retry: int  # re-transmission count (disconnected before overflow)
    time: float  # sender's clock (double), echoed by ACK to measure RTT
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


def set_socket_buffer_size(sock: socket, size: int = SOCKET_BUFFER_SIZE) -> None:
    """enlarge send/receive buffer as much as OS allows (default is ~200kb and drop packets on burst)"""
    for option in (s.SO_RCVBUF, s.SO_SNDBUF):
        request = size
        while 65536 <= request:
            try:
                if request <= sock.getsockopt(s.SOL_SOCKET, option):
                    break  # already enough
                sock.setsockopt(s.SOL_SOCKET, option, request)
                break
            except OSError:
                request //= 2  # e.g. macOS raise ENOBUFS when over kern.ipc.maxsockbuf


def set_dont_fragment(sock: socket, enable: bool) -> bool:
    """set/clear IPv4 don't-fragment flag, the option differs among OSes (return False if not supported)"""
    if sock.family != s.AF_INET:
        return False
    if sys.platform.startswith("linux"):
        option, value = IP_MTU_DISCOVER, (IP_PMTUDISC_DO if enable else IP_PMTUDISC_DONT)
    elif sys.platform == "darwin":
        option, value = IP_DONTFRAG, int(enable)
    elif sys.platform == "win32":
        option, value = IP_DONTFRAGMENT, int(enable)
    else:
        return False
    try:
        sock.setsockopt(s.IPPROTO_IP, option, value)
        return True
    except OSError:
        return False


def get_formal_address_format(address: '_WildAddress', family: int = s.AF_INET) -> '_Address':
    """tuple of ipv4/6 correct address format"""
    assert isinstance(address, tuple), "cannot recognize bytes or str format"
    for _, _, _, _, addr in s.getaddrinfo(str(address[0]), int(address[1]), family, s.SOCK_STREAM):
        return addr
    else:
        raise ConnectionError("not found correct ip format of {}".format(address))


class SecureReliableSocket(socket):
    __slots__ = [
        "_timeout", "span", "address", "shared_key", "mtu_size",
        "sender_seq", "sender_buffer", "sender_buffer_bytes", "sender_buffer_lock", "sender_cond",
        "sender_sacked", "sender_lost", "sender_lost_queue", "sender_socket_optional",
        "rack_xmit_ts", "rto_start", "tlp_sent", "cc", "pacer",
        "receiver_seq", "receiver_unread_size", "receiver_socket", "receiver_temporary",
        "receiver_ack_pending", "receiver_ack_needed", "receiver_echo_time", "receiver_last_packet", "last_ack_time",
        "receiver_output", "receiver_feeder",
        "broadcast_hook_fnc", "loss", "try_connect", "established", "rtt"]

    def __init__(self, family: int = s.AF_INET, timeout: float = 21.0, span: float = 3.0) -> None:
        """
        :param family: socket type AF_INET or AF_INET6
        :param timeout: auto socket close by the time passed (sec)
        :param span: check socket status by the span (sec)
        """
        # read buffer: this stream socket is connected to `receiver_feeder` on loopback,
        # received data is written to the feeder so recv() & select() work like a normal socket
        # note: don't connect the socket to itself, macOS refuse it with EINVAL (issue #5)
        super().__init__(family, s.SOCK_STREAM)
        with socket(family, s.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1" if family == s.AF_INET else "::1", 0))
            listener.listen(8)
            listener.settimeout(10.0)
            super().connect(listener.getsockname())
            self_address = super().getsockname()
            while True:
                feeder, feeder_peer = listener.accept()
                if feeder_peer[:2] == self_address[:2]:
                    break
                feeder.close()  # someone else connected to the listener
        feeder.setblocking(True)
        self.receiver_feeder = feeder

        # inner params
        self._timeout = timeout
        self.span = span
        self.address: '_Address' = None
        self.shared_key: bytes = None
        self.mtu_size = 0  # 1472b

        # sender params
        self.sender_seq = CycInt(1)  # next send sequence
        self.sender_buffer: 'OrderedDict[int, _Segment]' = OrderedDict()  # sent & not ACKed yet
        self.sender_buffer_bytes = 0  # total data size in sender_buffer
        self.sender_buffer_lock = threading.Lock()
        self.sender_cond = threading.Condition(self.sender_buffer_lock)  # notified when buffer has space
        self.sender_sacked = 0  # number of SACKed segments in sender_buffer
        self.sender_lost = 0  # number of segments marked lost (not retransmitted yet)
        self.sender_lost_queue: Deque[int] = deque()  # sequences to retransmit
        self.sender_socket_optional: Optional[socket] = None
        self.rack_xmit_ts = 0.0  # transmission time of the most recently delivered segment (RACK)
        self.rto_start = 0.0  # retransmission timer started at
        self.tlp_sent = False  # tail loss probe is sent after last progress

        # receiver params
        self.receiver_seq = CycInt(1)  # next receive sequence
        self.receiver_unread_size = 0
        self.receiver_socket = socket(family, s.SOCK_DGRAM)
        set_socket_buffer_size(self.receiver_socket)
        self.receiver_temporary: 'Dict[CycInt, Packet]' = dict()  # out-of-order packets
        self.receiver_ack_pending = 0  # in-order packets not acknowledged yet
        self.receiver_ack_needed = False  # should send ACK immediately (gap, duplicate or PSH)
        self.receiver_echo_time = 0.0  # time field of the last received data packet
        self.receiver_last_packet: Optional[Packet] = None
        self.receiver_output: 'List[bytes]' = list()  # data to be pushed to the read buffer at once
        self.last_ack_time = 0.0

        # broadcast hook
        # note: don't block this method or backend thread will be broken
        self.broadcast_hook_fnc: Optional['_BroadcastHook'] = None

        # round trip time & retransmission timeout
        self.rtt = RttEstimator()
        # congestion control & pacing
        self.cc = CongestionControl()
        self.pacer = Pacer()

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

    def bind(self, _address: '_WildAddress') -> None:
        raise NotImplementedError("don't use bind() method")

    def connect(self, address: '_WildAddress') -> None:
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
            set_socket_buffer_size(self.sender_socket_optional)
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
        for _ in range(int(self._timeout / self.span)):
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
        set_dont_fragment(self.receiver_socket, True)
        self.mtu_size = self._find_mtu_size()
        set_dont_fragment(self.receiver_socket, False)
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
        for _ in range(int(self._timeout / wait)):
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
        """receive packets, reorder sequence, fill output buffer & manage retransmission"""
        last_receive_time = clock()
        self.last_ack_time = clock()
        self.receiver_socket.setblocking(False)
        closing = False

        while not closing and not self.is_closed:
            # wake up often enough to check the retransmission timer
            if self.sender_buffer:
                select_timeout = min(self.span, max(0.002, self.rtt.pto / 2.0))
            else:
                select_timeout = min(self.span, IDLE_SELECT_TIMEOUT)
            try:
                r, _w, _x = select([self.receiver_socket.fileno()], [], [], select_timeout)
            except (OSError, ValueError):
                break  # socket closed
            now = clock()

            # retransmission timeout
            self._check_retransmit_timeout(now)

            # send ack as ping (stream may be free)
            if self.span < now - self.last_ack_time:
                self._send_ack(0.0)

            # connection may be broken
            if self._timeout < now - last_receive_time:
                self._send_control(CONTROL_FIN, b'stream may be broken')
                break

            # just socket select timeout (no data received yet)
            if len(r) == 0:
                continue

            # read datagrams queued in the socket
            for _ in range(RECEIVE_BATCH_SIZE):
                try:
                    data, _addr = self.receiver_socket.recvfrom(65536)
                except BlockingIOError:
                    break  # socket is empty
                except ConnectionResetError:
                    continue  # ICMP port unreachable (Windows)
                except OSError:
                    closing = True
                    break
                try:
                    packet = bin2packet(self._decrypt(data))
                except (ValueError, StructError):
                    continue  # decrypt failed or broken packet
                last_receive_time = clock()
                if not self._on_packet(packet):
                    closing = True
                    break

            # acknowledge received packets at once
            if not closing and (self.receiver_ack_needed or 0 < self.receiver_ack_pending):
                self._send_ack(self.receiver_echo_time)

            # deliver received data to the read buffer at once (1 syscall per batch)
            self._flush_receive_buffer()

        # close
        self._flush_receive_buffer()
        log.debug("srudp socket is closing now")
        self.close()

    def _on_packet(self, packet: Packet) -> bool:
        """handle received packet, return False when close"""
        # receive ack
        if packet.control & CONTROL_ACK:
            self._on_ack(packet)
            return True

        # receive reset
        if packet.control & CONTROL_FIN:
            self._send_control(CONTROL_FIN, b'be notified fin or reset')
            return False

        # deprecated: retransmission is requested by selective ACK
        if packet.control & CONTROL_RTM:
            return True

        # broadcast packet
        if packet.control & CONTROL_BCT:
            last_packet = self.receiver_last_packet
            if self.broadcast_hook_fnc is not None:
                self.broadcast_hook_fnc(packet, self)
            elif last_packet is None or last_packet.control & CONTROL_EOF:
                self._push_receive_buffer(packet.data)
            else:
                # note: acquire realtime response
                log.debug("throw away %s", packet)
            return True

        # normal data packet
        return self._on_data(packet)

    def _on_data(self, packet: Packet) -> bool:
        """reorder data packets & push to buffer, return False when close"""
        temporary = self.receiver_temporary
        self.receiver_echo_time = packet.time

        if packet.sequence == self.receiver_seq:
            gap_filled = 0 < len(temporary)
            control = packet.control
            self.receiver_seq += 1
            self._push_receive_buffer(packet.data)
            count = 1
            # drain packets that arrived early and are in order now
            while self.receiver_seq in temporary:
                packet = temporary.pop(self.receiver_seq)
                control |= packet.control
                self.receiver_seq += 1
                self._push_receive_buffer(packet.data)
                count += 1
            self.receiver_last_packet = Packet(control, packet.sequence, packet.retry, packet.time, b'')
            self.receiver_ack_pending += count
            if gap_filled or control & CONTROL_PSH:
                self.receiver_ack_needed = True
            if ACK_EVERY <= self.receiver_ack_pending:
                self._send_ack(packet.time)

        elif self.receiver_seq < packet.sequence:
            # out of order: keep it & tell the gap to the sender by selective ACK
            if packet.sequence not in temporary:
                temporary[packet.sequence] = packet
                if MAX_TEMPORARY_PACKET_SIZE < len(temporary):
                    log.error("too many temporary packets stored")
                    return False
            self.receiver_ack_needed = True

        else:
            # duplicated packet: our ACK may be lost
            self.receiver_ack_needed = True
        return True

    def _send_ack(self, echo_time: float) -> None:
        """cumulative ACK with selective ACK blocks (only backend thread)"""
        temporary = self.receiver_temporary
        blocks = sack_blocks(self.receiver_seq, temporary.keys()) if temporary else []
        p = Packet(CONTROL_ACK, self.receiver_seq - 1, 0, clock(), ack_body(echo_time, blocks))
        self.sendto(self._encrypt(packet2bin(p)), self.address)
        self.receiver_ack_pending = 0
        self.receiver_ack_needed = False
        self.last_ack_time = clock()

    def _send_control(self, control: int, data: bytes) -> None:
        p = Packet(control, CYC_INT0, 0, clock(), data)
        self.sendto(self._encrypt(packet2bin(p)), self.address)

    def _on_ack(self, packet: Packet) -> None:
        """remove delivered segments, detect lost ones & retransmit"""
        echo_time, blocks = parse_ack_body(packet.data)
        now = clock()
        if 0.0 < echo_time:
            self.rtt.update(now - echo_time)

        with self.sender_buffer_lock:
            buffer = self.sender_buffer
            delivered = 0
            rack_xmit_ts = self.rack_xmit_ts

            # cumulative ACK: remove all seq <= ack
            ack = packet.sequence
            while buffer:
                seq = next(iter(buffer))
                if ack < seq:
                    break
                _, seg = buffer.popitem(last=False)
                self.sender_buffer_bytes -= len(seg.data)
                if seg.sacked:
                    self.sender_sacked -= 1
                else:
                    delivered += 1
                    if seg.lost:
                        seg.lost = False
                        self.sender_lost -= 1
                    rack_xmit_ts = max(rack_xmit_ts, seg.xmit_time)

            # selective ACK: mark received segments
            for first, last in blocks:
                for i in range(min(len(buffer), (last - first) % 0x100000000 + 1)):
                    seg = buffer.get((first + i) % 0x100000000)
                    if seg is None or seg.sacked:
                        continue
                    seg.sacked = True
                    self.sender_sacked += 1
                    delivered += 1
                    if seg.lost:
                        seg.lost = False
                        self.sender_lost -= 1
                    rack_xmit_ts = max(rack_xmit_ts, seg.xmit_time)

            self.rack_xmit_ts = rack_xmit_ts
            if 0 < delivered:
                self.rto_start = now  # restart retransmission timer
                self.tlp_sent = False
                self.cc.on_ack(delivered, self.rtt)
            if 0 < self.sender_sacked:
                lost_seq = self._detect_lost()
                if lost_seq is not None:
                    self.cc.on_loss(lost_seq, self.sender_seq)
            self.pacer.update(self.cc.cwnd, self.rtt.srtt, self.mtu_size, self.cc.in_slow_start)
            self._retransmit_lost(now)
            self.sender_cond.notify_all()

    def _detect_lost(self) -> Optional[CycInt]:
        """
        RACK: a segment sent sufficiently earlier than a delivered one is lost
        (reordering window is a quarter of min RTT)
        """
        assert self.sender_buffer_lock.locked(), 'unlocked send_buffer!'
        reorder_window = MIN_REORDER_WINDOW
        if self.rtt.min_rtt != float("inf"):
            reorder_window = max(reorder_window, self.rtt.min_rtt / 4.0)
        threshold = self.rack_xmit_ts - reorder_window
        first_lost: Optional[CycInt] = None
        for seq, seg in self.sender_buffer.items():
            if seg.sacked or seg.lost:
                continue
            if seg.xmit_time <= threshold:
                seg.lost = True
                self.sender_lost += 1
                self.sender_lost_queue.append(seq)
                self.loss += 1
                if first_lost is None:
                    first_lost = seg.sequence
        return first_lost

    def _pipe(self) -> int:
        """number of packets in flight"""
        return len(self.sender_buffer) - self.sender_sacked - self.sender_lost

    def _retransmit_lost(self, now: float) -> None:
        """retransmit segments marked lost (limited by congestion window)"""
        assert self.sender_buffer_lock.locked(), 'unlocked send_buffer!'
        while self.sender_lost_queue and self._pipe() < self.cc.cwnd:
            seg = self.sender_buffer.get(self.sender_lost_queue.popleft())
            if seg is None or not seg.lost:
                continue  # already delivered
            seg.lost = False
            self.sender_lost -= 1
            seg.retry = min(255, seg.retry + 1)
            seg.xmit_time = now
            self.sendto(self._encrypt(packet2bin(seg.to_packet())), self.address)

    def _send_probe(self, now: float) -> None:
        """retransmit the newest segment not SACKed yet (tail loss probe)"""
        assert self.sender_buffer_lock.locked(), 'unlocked send_buffer!'
        for seg in reversed(self.sender_buffer.values()):
            if seg.sacked:
                continue
            if seg.lost:
                seg.lost = False
                self.sender_lost -= 1
            seg.retry = min(255, seg.retry + 1)
            seg.xmit_time = now
            self.sendto(self._encrypt(packet2bin(seg.to_packet())), self.address)
            self.tlp_sent = True
            self.loss += 1
            return

    def _check_retransmit_timeout(self, now: float) -> None:
        """
        no ACK for PTO: tail loss probe, retransmit the newest segment to get SACK
          (lost segments sent after the last delivered one are never detected by RACK otherwise)
        no ACK for RTO: all segments in flight are lost, restart by slow start
        """
        with self.sender_buffer_lock:
            if len(self.sender_buffer) == 0:
                return
            elapsed = now - self.rto_start
            if elapsed < self.rtt.rto:
                if not self.tlp_sent and self.rtt.pto <= elapsed:
                    self._send_probe(now)
                return
            self.rtt.on_timeout()  # exponential backoff
            self.cc.on_timeout(self.sender_seq)
            self.rto_start = now
            self.sender_lost_queue.clear()
            self.sender_lost = 0
            for seq, seg in self.sender_buffer.items():
                if seg.sacked:
                    continue
                seg.lost = True
                self.sender_lost += 1
                self.sender_lost_queue.append(seq)
                self.loss += 1
            self._retransmit_lost(now)

    def _push_receive_buffer(self, data: bytes) -> None:
        """just append new data to buffer (delivered by _flush_receive_buffer)"""
        if data:
            self.receiver_output.append(data)

    def _flush_receive_buffer(self) -> None:
        if len(self.receiver_output) == 0:
            return
        data = b"".join(self.receiver_output)
        self.receiver_output.clear()
        if self.receiver_feeder.fileno() == -1:
            return  # already closed
        try:
            self.receiver_feeder.sendall(data)
        except OSError:
            return  # closed by user
        self.receiver_unread_size += len(data)

    def _send_buffer_is_full(self) -> bool:
        assert self.sender_buffer_lock.locked(), 'unlocked send_buffer!'
        return SEND_BUFFER_SIZE < self.sender_buffer_bytes

    def _can_send_new(self) -> bool:
        """congestion window has space & no lost segments waiting for retransmission"""
        assert self.sender_buffer_lock.locked(), 'unlocked send_buffer!'
        return self.sender_lost == 0 and self._pipe() < self.cc.cwnd and not self._send_buffer_is_full()

    def get_window_size(self) -> int:
        """maximum size of data you can send at once"""
        # Packet = [nonce 24b][tag 16b][static 14b][data xb]
        return self.mtu_size - CIPHER_OVERHEAD - packet_struct.size

    def send(self, data: 'ReadableBuffer', flags: int = 0) -> int:
        """over write low-level method for compatibility"""
        assert flags == 0, "unrecognized flags"
        size = memoryview(data).nbytes
        self.sendall(data)
        return size

    def _send(self, data: memoryview) -> int:
        """warning: row-level method"""
        window_size = self.get_window_size()
        length = len(data) // window_size
        send_size = 0
        for i in range(length + 1):
            # wait for congestion window
            with self.sender_cond:
                while self.established and not self._can_send_new():
                    if not self.sender_cond.wait(self.span):
                        log.debug("waiting for congestion window..")
            if not self.established:
                raise ConnectionAbortedError('disconnected')

            # wait for pacing
            throw = data[window_size * i:window_size * (i + 1)]
            delay = self.pacer.delay(len(throw) + packet_struct.size)
            while 0.0 < delay:
                sleep(delay)
                delay = self.pacer.delay(len(throw) + packet_struct.size)

            # control flag
            control = 0b00000000
            if i == length:
                control |= CONTROL_PSH | CONTROL_EOF

            # send one packet
            with self.sender_buffer_lock:
                now = clock()
                if len(self.sender_buffer) == 0:
                    self.rto_start = now  # start retransmission timer
                seg = _Segment(control, self.sender_seq, throw.tobytes(), now)
                self.sender_buffer[int(seg.sequence)] = seg
                self.sender_buffer_bytes += len(seg.data)
                self.sender_seq += 1
            self.sendto(self._encrypt(packet2bin(seg.to_packet())), self.address)
            send_size += len(throw)
        return send_size

    def sendto(self, data: 'ReadableBuffer', address: '_Address') -> int:  # type: ignore
        """row-level method: guarded by `sender_buffer_lock`, don't use.."""
        # note: sendto() after bind() with different port cause OSError on recvfrom()
        if self.is_closed:
            return 0
        try:
            if self.sender_socket_optional is None:
                return self.receiver_socket.sendto(data, address)
            else:
                return self.sender_socket_optional.sendto(data, address)
        except OSError as e:
            if self.established and e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.ENOBUFS):
                return 0  # OS buffer is full, same as packet loss (retransmitted later)
            raise

    def sendall(self, data: 'ReadableBuffer', flags: int = 0) -> None:
        """high-level method, use this instead of send()"""
        assert flags == 0, "unrecognized flags"
        if not self.established:
            raise ConnectionAbortedError('disconnected')
        view = memoryview(data).cast("B")
        if len(view) == 0:
            return
        send_size = self._send(view)
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
        """
        encrypt by XChaCha20-Poly1305 (AEAD)
        192bit random nonce is safe to generate for each packet (no counter required)
        and about twice as fast as AES-GCM on PyCryptodome because GCM needs a costly setup per nonce
        """
        nonce = os.urandom(NONCE_SIZE)
        cipher = ChaCha20_Poly1305.new(key=self.shared_key, nonce=nonce)
        enc, tag = cipher.encrypt_and_digest(data)
        # output length = 24bytes + 16bytes + N(=data)bytes
        return nonce + tag + enc

    def _decrypt(self, data: bytes) -> bytes:
        """decrypt by XChaCha20-Poly1305, ValueError raised when verify failed"""
        if len(data) < CIPHER_OVERHEAD:
            raise ValueError("too short data")
        cipher = ChaCha20_Poly1305.new(key=self.shared_key, nonce=data[:NONCE_SIZE])
        return cipher.decrypt_and_verify(data[CIPHER_OVERHEAD:], data[NONCE_SIZE:CIPHER_OVERHEAD])

    def getsockname(self) -> '_Address':
        """self bind info or raise OSError"""
        if self.is_closed:
            raise OSError("socket is closed")
        else:
            return self.receiver_socket.getsockname()  # type: ignore

    def getpeername(self) -> '_Address':
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
            try:
                self.sendto(self._encrypt(packet2bin(p)), self.address)
            except OSError:
                pass
        # note: close all inner sockets even if not established (e.g. connect() failed)
        self.receiver_socket.close()
        self.receiver_feeder.close()
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
