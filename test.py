from srudp import SecureReliableSocket, Packet, sack_blocks, ack_body, parse_ack_body
from typing import Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor
from time import sleep
import socket as s
import random
import unittest
import asyncio
import threading
import logging
import os


logger = logging.getLogger("srudp")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '[%(levelname)-6s] [%(threadName)-10s] [%(asctime)-24s] %(message)s')
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(formatter)
logger.addHandler(sh)

IS_WINDOWS = os.name == 'nt'


def has_ipv6_loopback() -> bool:
    if not s.has_ipv6:
        return False
    try:
        with s.socket(s.AF_INET6, s.SOCK_DGRAM) as sock:
            sock.bind(("::1", 0))
        return True
    except OSError:
        return False


class LossySocket(SecureReliableSocket):
    """drop & reorder outgoing datagrams after established (for test)"""
    __slots__ = ["drop_rate", "reorder_rate", "rand", "holding", "hold_lock"]

    def __init__(self, drop_rate: float, reorder_rate: float, seed: int) -> None:
        super().__init__()
        self.drop_rate = drop_rate
        self.reorder_rate = reorder_rate
        self.rand = random.Random(seed)
        self.holding: Optional[Tuple[bytes, Any]] = None
        self.hold_lock = threading.Lock()

    def _release(self) -> None:
        with self.hold_lock:
            held, self.holding = self.holding, None
        if held is not None:
            super().sendto(*held)

    def sendto(self, data, address):  # type: ignore
        if not self.established:
            return super().sendto(data, address)
        with self.hold_lock:
            x = self.rand.random()
            if x < self.drop_rate:
                return len(data)  # lost
            if self.holding is None and x < self.drop_rate + self.reorder_rate:
                # send after the next one (or 5ms later)
                self.holding = (bytes(data), address)
                threading.Timer(0.005, self._release).start()
                return len(data)
        size = super().sendto(data, address)
        self._release()
        return size


class TestFunctions(unittest.TestCase):
    def test_sack_blocks(self):
        assert sack_blocks(10, []) == []
        assert sack_blocks(10, [12, 13, 14, 20, 22, 21]) == [(12, 14), (20, 22)]
        # cycle around 0xffffffff
        assert sack_blocks(0xfffffffe, [0xffffffff, 0, 1, 5]) == [(0xffffffff, 1), (5, 5)]
        assert sack_blocks(0, [2, 4, 6, 8], limit=2) == [(2, 2), (4, 4)]

    def test_ack_body(self):
        assert parse_ack_body(ack_body(1.5, [(1, 2), (5, 9)])) == (1.5, [(1, 2), (5, 9)])
        assert parse_ack_body(b'as ping') == (0.0, [])


class TestSocket(unittest.TestCase):
    def setUp(self) -> None:
        logger.info("start")
        self.port = random.randint(10000, 30000)
        self.executor = ThreadPoolExecutor(4, thread_name_prefix="Thread")

    def tearDown(self) -> None:
        self.executor.shutdown(True)
        logger.info("end")

    def test_basic(self):
        logger.info("start test_basic()")
        sock1 = SecureReliableSocket()
        sock2 = SecureReliableSocket()
        sock1.settimeout(5.0)
        sock2.settimeout(5.0)

        # connect
        fut1 = self.executor.submit(sock1.connect, ("127.0.0.1", self.port))
        fut2 = self.executor.submit(sock2.connect, ("127.0.0.1", self.port))

        fut1.result(10.0)
        fut2.result(10.0)

        # connection info
        assert sock1.getpeername() == sock2.getsockname(), (sock1.getpeername(), sock2.getsockname())

        # normal sending
        sock1.sendall(b"hello world")
        assert sock2.recv(1024) == b"hello world"

        # broadcast sending
        sock2.broadcast(b"good man")
        assert sock1.recv(1024) == b"good man"

        # broadcast hook fnc
        def hook_fnc(packet: Packet, _sock: SecureReliableSocket):
            assert packet.data == b"broadcasting now"
        sock1.broadcast_hook_fnc = hook_fnc
        sock2.broadcast(b"broadcasting now")

        # close
        sock1.close()
        sock2.close()

    def test_big_size(self):
        logger.info("start test_big_size()")
        sock1 = SecureReliableSocket()
        sock2 = SecureReliableSocket()
        sock1.settimeout(5.0)
        sock2.settimeout(5.0)

        # connect
        fut1 = self.executor.submit(sock1.connect, ("127.0.0.1", self.port))
        fut2 = self.executor.submit(sock2.connect, ("127.0.0.1", self.port))

        fut1.result(10.0)
        fut2.result(10.0)

        # 1M bytes data
        data = os.urandom(1000000)
        self.executor.submit(sock2.sendall, data)\
            .add_done_callback(lambda fut: fut.result())
        received = b""
        while True:
            try:
                received += sock1.recv(4096)
                if 1000000 <= len(received):
                    break
            except s.timeout:
                break
        assert received == data, (len(received), len(data))

        # close
        sock1.close()
        sock2.close()

    def test_lossy_network(self):
        logger.info("start test_lossy_network()")
        # both directions drop 5% & reorder 5% of packets
        sock1 = LossySocket(0.05, 0.05, seed=1)
        sock2 = LossySocket(0.05, 0.05, seed=2)
        sock1.settimeout(10.0)

        fut1 = self.executor.submit(sock1.connect, ("127.0.0.1", self.port))
        fut2 = self.executor.submit(sock2.connect, ("127.0.0.1", self.port))
        fut1.result(10.0)
        fut2.result(10.0)

        size = 2000000
        data = os.urandom(size)
        fut = self.executor.submit(sock2.sendall, data)
        received = bytearray()
        while len(received) < size:
            r = sock1.recv(65536)
            if len(r) == 0:
                break
            received += r
        fut.result(10.0)
        assert received == data, (len(received), len(data))
        assert 0 < sock2.loss, sock2

        sock1.close()
        sock2.close()

    def test_ipv6(self):
        logger.info("start test_ipv6()")
        # https://docs.travis-ci.com/user/reference/overview/#virtualisation-environment-vs-operating-system
        if not has_ipv6_loopback():
            self.skipTest("ipv6 isn't supported")

        sock1 = SecureReliableSocket(s.AF_INET6)
        sock2 = SecureReliableSocket(s.AF_INET6)
        sock1.settimeout(5.0)
        sock2.settimeout(5.0)

        # connect
        fut1 = self.executor.submit(sock1.connect, ("::1", self.port))
        sleep(1.0)
        fut2 = self.executor.submit(sock2.connect, ("::1", self.port))

        fut1.result(10.0)
        fut2.result(10.0)

        assert sock1.established and sock2.established, (sock1, sock2)

        # close
        sock1.close()
        sock2.close()

    def test_asyncio(self):
        logger.info("start test_asyncio()")
        # note: ProactorEventLoop (Windows default) writes to the socket handle directly
        # and bypasses SecureReliableSocket.send(), use SelectorEventLoop instead
        loop = asyncio.SelectorEventLoop() if IS_WINDOWS else asyncio.new_event_loop()

        sock1 = SecureReliableSocket()
        sock2 = SecureReliableSocket()
        sock1.setblocking(False)
        sock2.setblocking(False)

        async def coro():
            fut1 = loop.run_in_executor(self.executor, sock1.connect, ("127.0.0.1", self.port))
            fut2 = loop.run_in_executor(self.executor, sock2.connect, ("127.0.0.1", self.port))
            await fut1
            await fut2

            reader1, writer1 = await asyncio.open_connection(sock=sock1)
            reader2, writer2 = await asyncio.open_connection(sock=sock2)

            writer1.write(b"nice world")
            await writer1.drain()
            received = await reader2.read(1024)
            assert received == b"nice world"

            writer1.close()
            writer2.close()

        loop.run_until_complete(coro())
        loop.close()
        sleep(1.0)
        assert sock1.is_closed and sock2.is_closed, (sock1, sock2)


if __name__ == "__main__":
    unittest.main()
