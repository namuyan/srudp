from srudp import SecureReliableSocket, Packet
from concurrent.futures import ThreadPoolExecutor
from time import sleep
import socket as s
import random
import unittest
import asyncio
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

IS_TRAVIS = os.getenv('TRAVIS') == 'true'
IS_WINDOWS = os.name == 'nt'


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

    def test_ipv6(self):
        logger.info("start test_ipv6()")
        # https://docs.travis-ci.com/user/reference/overview/#virtualisation-environment-vs-operating-system
        if IS_TRAVIS:
            return unittest.skip("ipv6 isn't supported")

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
        if IS_TRAVIS and IS_WINDOWS:
            return unittest.skip("travis's windows fail stream drain()")

        loop = asyncio.get_event_loop()

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
        sleep(1.0)
        assert sock1.is_closed and sock2.is_closed, (sock1, sock2)


if __name__ == "__main__":
    unittest.main()
