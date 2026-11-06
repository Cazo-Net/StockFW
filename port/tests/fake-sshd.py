"""A listener that the kernel names "sshd" (prctl PR_SET_NAME), on a free
127.0.0.1 port, with one established session from 127.0.0.3.  Prints
"PORT" when ready and waits until stdin closes.  Used by test-core.sh to
check that the SSH sessions an apply keeps follow sshd to any port.

  fake-sshd.py               as above
  fake-sshd.py --activated   systemd socket activation: this process
                             (not named sshd, a lower pid) opens the
                             listener and keeps it, and a child named
                             sshd inherits it and takes the session, as
                             pid 1 and sshd do with ssh.socket
  fake-sshd.py --exec CMD..  as the first form, then runs CMD as a child
                             of the "sshd" (the session's shell would
                             be) with PORT appended, prints its output
                             instead of PORT, and waits for stdin
"""
import ctypes
import os
import socket
import subprocess
import sys

libc = ctypes.CDLL(None)


def listen():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    return server


def session(server):
    port = server.getsockname()[1]
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.bind(("127.0.0.3", 0))
    client.connect(("127.0.0.1", port))
    peer, _ = server.accept()
    return port, client, peer


if len(sys.argv) > 1 and sys.argv[1] == "--activated":
    server = listen()
    child = os.fork()
    if child == 0:
        libc.prctl(15, b"sshd", 0, 0, 0)          # PR_SET_NAME
        port, client, peer = session(server)
        print(port, flush=True)
        sys.stdin.read()
        os._exit(0)
    # The "systemd" side keeps its copy of the listener open.
    os.waitpid(child, 0)
    sys.exit(0)

libc.prctl(15, b"sshd", 0, 0, 0)                  # PR_SET_NAME
server = listen()
port, client, peer = session(server)

if len(sys.argv) > 2 and sys.argv[1] == "--exec":
    out = subprocess.run(sys.argv[2:] + [str(port)], stdout=subprocess.PIPE,
                         text=True).stdout
    print(out.strip(), flush=True)
else:
    print(port, flush=True)
sys.stdin.read()
