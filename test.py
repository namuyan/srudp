from srudp import SecureReliableSocket, Packet
from concurrent.futures import ThreadPoolExecutor
from time import sleep
import socket as s
import random
import unittest
import asyncio
import os


class TestSocket(unittest.TestCase):
    def setUp(self) -> None:
        self.port1 = random.randint(10000, 30000)
        self.port2 = random.randint(10000, 30000)
        self.executor = ThreadPoolExecutor(4)

    def tearDown(self) -> None:
        self.executor.submit(True)

    def test_basic(self):
        sock1 = SecureReliableSocket()
        sock2 = SecureReliableSocket()
        sock1.settimeout(5.0)
        sock2.settimeout(5.0)

        # connect
        fut1 = self.executor.submit(sock1.connect, ("127.0.0.1", self.port1), self.port2)
        fut2 = self.executor.submit(sock2.connect, ("127.0.0.1", self.port2), self.port1)

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
        sock1 = SecureReliableSocket()
        sock2 = SecureReliableSocket()
        sock1.settimeout(5.0)
        sock2.settimeout(5.0)

        # connect
        fut1 = self.executor.submit(sock1.connect, ("127.0.0.1", self.port1), self.port2)
        fut2 = self.executor.submit(sock2.connect, ("127.0.0.1", self.port2), self.port1)

        fut1.result(10.0)
        fut2.result(10.0)

        # 1M bits data
        data = os.urandom(1000000)
        self.executor.submit(sock2.sendall, data)
        received = b""
        while True:
            try:
                received += sock1.recv(4096)
                if 1000000 <= len(received):
                    break
            except s.timeout:
                break
        assert received == data

        # close
        sock1.close()
        sock2.close()

    def test_ipv6(self):
        sock1 = SecureReliableSocket(s.AF_INET6)
        sock2 = SecureReliableSocket(s.AF_INET6)
        sock1.settimeout(5.0)
        sock2.settimeout(5.0)

        # connect
        fut1 = self.executor.submit(sock1.connect, ("::1", self.port1), self.port2)
        sleep(1.0)
        fut2 = self.executor.submit(sock2.connect, ("::1", self.port2), self.port1)

        fut1.result(10.0)
        fut2.result(10.0)

        assert sock1.established and sock2.established, (sock1, sock2)

        # close
        sock1.close()
        sock2.close()

        assert sock1.is_closed and sock2.is_closed, (sock1, sock2)

    def test_asyncio(self):
        loop = asyncio.get_event_loop()

        sock1 = SecureReliableSocket()
        sock2 = SecureReliableSocket()
        sock1.settimeout(None)
        sock2.settimeout(None)

        async def coro():
            fut1 = loop.run_in_executor(self.executor, sock1.connect, ("127.0.0.1", self.port1), self.port2)
            fut2 = loop.run_in_executor(self.executor, sock2.connect, ("127.0.0.1", self.port2), self.port1)
            await fut1
            await fut2

            reader1, writer1 = await asyncio.open_connection(sock=sock1)
            reader2, writer2 = await asyncio.open_connection(sock=sock2)

            writer1.write(b"nice world")
            await writer1.drain()
            assert await reader2.read(1024) == b"nice world"

            writer1.close()
            writer2.close()

        loop.run_until_complete(coro())
        assert sock1.is_closed and sock2.is_closed, (sock1, sock2)


if __name__ == "__main__":
    unittest.main()
