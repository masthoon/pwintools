import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

# Connect TCP 127.0.0.1:8888
r = Remote('127.0.0.1', 8888)
print(r)
# Send 'TEST' and waits for 'quit'
r.sendline('TEST')
buf = ''
while buf != 'quit\n':
    buf = r.recvall()
    print(buf)
r.interactive()
