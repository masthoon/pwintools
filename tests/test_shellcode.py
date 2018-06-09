import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

log.log_level = 'debug'

def run_shellcode(sc, debug = False):
    if debug:
        log.debug(disasm(sc))
        log.debug(hexdump(sc))
    import windows.test
    notepad = Process(r"C:\Windows\system32\notepad.exe", CREATE_SUSPENDED)
    if debug:
        notepad.spawn_debugger()
        log.info("Press 'g' in debugger!")
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


test_shellcode1()
# test_shellcode2()
test_shellcode3()