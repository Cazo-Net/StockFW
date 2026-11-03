"""A listener that the kernel names "sshd" (prctl PR_SET_NAME), on a free
127.0.0.1 port, with one established session from 127.0.0.3.  Prints
"PORT" when ready and waits until stdin closes.  Used by test-core.sh to
check that the SSH sessions an apply keeps follow sshd to any port.
"""
import ctypes
import socket
import sys

libc = ctypes.CDLL(None)
libc.prctl(15, b"sshd", 0, 0, 0)          # PR_SET_NAME

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 0))
server.listen(4)
port = server.getsockname()[1]

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("127.0.0.3", 0))
client.connect(("127.0.0.1", port))
peer, _ = server.accept()

print(port, flush=True)
sys.stdin.read()
