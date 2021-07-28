import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

escape = len(sys.argv) > 1

# Connect TCP 127.0.0.1:8888
r = Remote('127.0.0.1', 8888)
log.info(r)
# Send 'PING' and waits for 'PONG' and detect connection closed
r.sendline('PING')
buf = r.recvall()
assert(buf == b'PONG')
r.write('OK' + '\n')

assert(r.recvuntil(b':') == b'Non-ASCII stuff:')
assert(r.recvn(2) == b'\x04\x08')
assert(r.recvline().strip() == b':')
assert(r.recv(4) == b'QUIT')

log.success("Going interactive")
r.interactive(escape=escape)
