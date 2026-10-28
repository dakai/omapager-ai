"""The reply text must reach the bus inside the message, not in an argument.

`sendReply` cannot go through `busctl`: that would put the user's reply into a
third process's argv. `bin/omapager-kdeconnect` marshals the call itself, so this
test plays the bus over a real Unix socket and inspects the bytes it receives.

The fake bus answers every call with an empty method return, except the one it is
told to refuse, which is how the error path is exercised.
"""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))


def load():
    name = 'bus_client_under_test'
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / 'bin/omapager-kdeconnect'))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def read_exactly(stream, size):
    data = bytearray()
    while len(data) < size:
        block = stream.recv(size - len(data))
        if not block:
            raise EOFError
        data.extend(block)
    return bytes(data)


def read_message(stream):
    head = read_exactly(stream, 16)
    body_length = struct.unpack('<I', head[4:8])[0]
    array_length = struct.unpack('<I', head[12:16])[0]
    total = ((16 + array_length + 7) & ~7) + body_length
    return head + read_exactly(stream, total - 16)


def method_return(serial=1):
    return b'l\x02\x01\x01' + struct.pack('<I', 0) + struct.pack('<I', serial) + struct.pack('<I', 0)


def error_return(serial=2):
    return b'l\x03\x01\x01' + struct.pack('<I', 0) + struct.pack('<I', serial) + struct.pack('<I', 0)


class FakeBus:
    """Accepts one client, answers Hello, then records the next call."""

    def __init__(self, refuse=False):
        self.refuse = refuse
        self.call = b''
        self.received = []
        self.ready = threading.Event()

    def serve(self, path):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen(1)
            self.ready.set()
            connection, _ = server.accept()
            with connection:
                self._auth(connection)
                self.received.append(read_message(connection))   # Hello
                connection.sendall(method_return(1))
                self.call = read_message(connection)
                connection.sendall(error_return(2) if self.refuse else method_return(2))

    def _auth(self, connection):
        line = bytearray()
        while not line.endswith(b'\r\n'):
            line.extend(connection.recv(1))
        assert line.startswith(b'\x00AUTH EXTERNAL '), line
        connection.sendall(b'OK ' + b'a' * 32 + b'\r\n')
        begun = bytearray()
        while not begun.endswith(b'\r\n'):
            begun.extend(connection.recv(1))
        assert begun == b'BEGIN\r\n', begun


class ReplyTransport(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.temp = tempfile.TemporaryDirectory()
        self.runtime = Path(self.temp.name)
        os.chmod(self.runtime, 0o700)
        self.socket_path = self.runtime / 'bus'

    def tearDown(self):
        self.temp.cleanup()

    def run_call(self, refuse, text):
        bus = FakeBus(refuse=refuse)
        server = threading.Thread(target=bus.serve, args=(self.socket_path,), daemon=True)
        server.start()
        self.assertTrue(bus.ready.wait(5), 'the fake bus never started')
        address = 'unix:path=' + str(self.socket_path)
        with patch.dict(os.environ, {'DBUS_SESSION_BUS_ADDRESS': address}):
            result = self.module.call('/modules/kdeconnect/devices/d/notifications/1',
                                      'org.kde.kdeconnect.device.notifications.notification',
                                      'sendReply', text)
        server.join(5)
        self.assertFalse(server.is_alive(), 'the client never completed the exchange')
        return result, bus

    def test_text_is_carried_in_the_message_body(self):
        text = 'see you at Zx9-unique-private-message-4711'
        result, bus = self.run_call(False, text)
        self.assertTrue(result)
        # The body of the call, after its header, is one string: length, bytes, NUL.
        self.assertIn(struct.pack('<I', len(text.encode())) + text.encode() + b'\0', bus.call)
        for field in (b'/modules/kdeconnect/devices/d/notifications/1',
                      b'org.kde.kdeconnect.device.notifications.notification',
                      b'sendReply'):
            self.assertIn(field, bus.call)
        self.assertEqual(self.module.call and len(bus.received), 1)

    def test_an_error_reply_is_a_failure(self):
        result, bus = self.run_call(True, 'anything')
        self.assertFalse(result)
        self.assertIn(b'sendReply', bus.call)

    def test_unsupported_address_is_refused(self):
        with patch.dict(os.environ, {'DBUS_SESSION_BUS_ADDRESS': 'tcp:host=localhost,port=1'}):
            with self.assertRaises(OSError):
                self.module.call('/x', 'y', 'z', 'text')

    def test_signature_and_argument_encoding_round_trip(self):
        """A non-ASCII reply must arrive as UTF-8 bytes, length in bytes."""
        text = '日本語の返信'
        result, bus = self.run_call(False, text)
        self.assertTrue(result)
        self.assertIn(struct.pack('<I', len(text.encode())) + text.encode() + b'\0', bus.call)


if __name__ == '__main__':
    unittest.main()
