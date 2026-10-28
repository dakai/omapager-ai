"""Message text must not be readable from another local user's /proc.

KDE Connect forwards SMS and chat text into a notification, and the reply path
carries the user's answer back. Both are private between users on one machine.
argv is not: /proc/PID/cmdline is world-readable unless hidepid is set, while the
stdin pipe is not. So the helper is started with the text on a pipe and this test
looks for it in every process's command line while that helper is still alive.

The child blocks reading stdin because the pipe is never closed, which is what
keeps the window open long enough to scan. Nothing here talks to a bus.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SECRET = 'Zx9-unique-private-message-4711'
BWRAP = Path('/usr/bin/bwrap')


def command_lines():
    lines = []
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            raw = Path('/proc', entry, 'cmdline').read_bytes()
        except OSError:
            continue
        lines.append((entry, raw.replace(b'\0', b' ')))
    return lines


def sandbox_available():
    if not BWRAP.is_file() or not os.access(BWRAP, os.X_OK):
        return False
    probe = subprocess.run([str(ROOT / 'bin/omapager-run-helper'), 'status'],
                           capture_output=True, text=True, timeout=20)
    try:
        return json.loads(probe.stdout or '{}').get('sandboxOperational', False)
    except ValueError:
        return False


class CommandLinePrivacy(unittest.TestCase):
    def scan(self, argv, payload, sandboxed):
        environ = dict(os.environ)
        environ['OMAPAGER_REQUIRE_SANDBOX'] = '1' if sandboxed else '0'
        proc = subprocess.Popen(
            [str(ROOT / 'bin/omapager-run-kdeconnect'), *argv],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=environ)
        try:
            proc.stdin.write(json.dumps(payload).encode())
            proc.stdin.flush()          # never closed: the helper waits for EOF
            deadline = time.monotonic() + 10
            running = False
            while time.monotonic() < deadline:
                lines = command_lines()
                running = any(b'omapager-kdeconnect' in line or b'omapager-run-helper' in line
                              for _, line in lines)
                if running:
                    break
                time.sleep(0.02)
            self.assertTrue(running, 'the helper never started, so this proved nothing')
            for pid, line in command_lines():
                self.assertNotIn(SECRET.encode(), line,
                                 'private text in /proc/%s/cmdline' % pid)
            self.assertIsNone(proc.poll(), 'the helper exited instead of holding the pipe')
        finally:
            proc.kill()
            proc.wait()
            proc.stdin.close()

    def check(self, sandboxed):
        target = '/modules/kdeconnect/devices/device/notifications/1'
        for argv, payload in (
            (['find', 'Chat'], {'body': 'sender: ' + SECRET}),
            (['reply', target, 'Chat'], {'text': SECRET, 'body': SECRET}),
        ):
            with self.subTest(argv=argv, sandboxed=sandboxed):
                self.scan(argv, payload, sandboxed)

    def test_direct_mode(self):
        self.check(False)

    def test_sandboxed_mode(self):
        if not sandbox_available():
            self.skipTest('no operational bubblewrap on this host')
        self.check(True)


if __name__ == '__main__':
    unittest.main()
