import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

log.log_level = 'error'

escape = len(sys.argv) > 1

pwn = Process("pwn.exe")
pwn.interactive(escape=escape)
pwn.close()

