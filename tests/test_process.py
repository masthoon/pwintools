import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

log.log_level = 'warning'

# Simple process spawn and exit
cmd = Process(r"C:\Windows\System32\cmd.exe")
assert(cmd.check_initialized())
cmd.close()
assert(cmd.is_exit)

# Simple process with bytes type name
cmd = Process(b"C:\\Windows\\System32\\cmd.exe")
assert(cmd.check_initialized())
cmd.close()
assert(cmd.is_exit)

# Suspended process spawn and exit
notepad = Process(r"C:\Windows\system32\notepad.exe", CREATE_SUSPENDED)
assert(not notepad.check_initialized())
notepad.threads[0].resume()
notepad.wait_initialized()
assert(notepad.check_initialized())
notepad.close()
assert(notepad.is_exit)

# Process API test
cmd = Process(r"C:\Windows\System32\cmd.exe")
notepad = Process(r"C:\Windows\system32\notepad.exe", CREATE_SUSPENDED)
assert("combase.dll" in cmd.libs)
try:
    notepad.libs
    assert(0)
except Exception as e:
    assert("PEB not initialized" in str(e))

notepad.close()
cmd.close()

pwn = Process('pwn.exe')
assert(pwn.leak(0x402000, 7) == b'Welcome')
assert(pwn.search(b'cmd.exe') != 0)

WinExecPwn = pwn.get_import('kernel32.dll', 'WinExec')
assert(WinExecPwn == pwn.imports['kernel32.dll']['WinExec'].addr)

WinExecK32 = pwn.symbols['kernel32.dll']['WinExec']
assert(WinExecK32 == pwn.imports['kernel32.dll']['WinExec'].value)
assert(WinExecK32 == pwn.get_proc_address('kernel32.dll', 'WinExec'))
assert(WinExecK32 == u32(pwn.leak(pwn.imports['kernel32.dll']['WinExec'].addr, 4)))

pwn.close()