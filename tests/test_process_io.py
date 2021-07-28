import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

# CMD process IO read / write
cmd = Process(r"C:\Windows\System32\cmd.exe")
assert(cmd.read(17) == b'Microsoft Windows')
cmd.set_timeout(0.2)
assert(cmd.recvall().endswith(b'>'))
# Send a cmd
cmd.sendline("echo COUCOU")
assert(cmd.recvline().strip() == b'echo COUCOU')
assert(cmd.recvline().strip() == b"COUCOU")

cmd.send("ping -n 2 127.0.0.1 >NUL")
cmd.write(" && echo TIMEOUT")
cmd.sendline(b'')

# cmdline
assert(cmd.recvline().strip() == b'')
cmd.recvline()

try:
    log.log_level = 'critical'
    print(cmd.recvn(1))
    assert(0)
except EOFError:
    pass

# Allow 2s timeout
assert(cmd.recvline(timeout=2000).strip() == b"TIMEOUT")

# Non-ascii test
cmd.sendline(b"echo 123\x02\x04")
cmd.recvuntil(b'\n123')
assert(cmd.recvn(2) == b'\x02\x04')

cmd.close()

