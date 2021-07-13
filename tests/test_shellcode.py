import sys
import os.path
import time
sys.path.append(os.path.abspath(__file__ + "\..\.."))
from pwintools import *

log.log_level = 'debug'

def run_shellcode(sc, debug = False):
    if debug:
        # log.debug(disasm(sc))
        log.debug(hexdump(sc))
    notepad = Process(b"C:/Windows/system32/notepad.exe", CREATE_SUSPENDED)
    if debug:
        notepad.spawn_debugger()
        log.info("Press 'g' in debugger!")
    notepad.execute(sc, notepad.virtual_alloc(0x1000))
    return notepad

def test_shellcode_winexec():
    pattern = b' PROBABLY_WILL_NOT_FIND_THIS_FILE'
    sc = shellcraft.amd64.WinExec(b"notepad.exe" + pattern)
    test = run_shellcode(sc)
    time.sleep(0.5)
    notepads = [p for p in windows.system.processes if p.name == "notepad.exe"]
    assert(any([pattern in p.peb.commandline.str.encode('utf-16be').replace(b'\0', b'') for p in notepads]))
    test.close()
    # Close the child process
    for n_proc in notepads:
        if pattern in n_proc.peb.commandline.str:
            n_proc.exit(0)

def test_shellcode_loadlibrary():
    # Works over SMB or WebDAV \\IP\X\X.dll
    #  Or with fullpath D:\Desktop\XYZ\A.dll
    sc = shellcraft.amd64.LoadLibrary(b"C:/Windows/System32/ntoskrnl.exe")
    test = run_shellcode(sc)
    time.sleep(0.5)
    assert('ntoskrnl.exe' in test.libs)
    test.close()

def test_shellcode_rwx():
    sc = shellcraft.amd64.AllocRWX(0x1234000, 0xfeeb) # infinite loop
    test = run_shellcode(sc)
    time.sleep(0.5)
    assert(test.query_memory(0x1234000).Protect == PAGE_EXECUTE_READWRITE)
    test.close()


#test_shellcode_winexec()
#test_shellcode_loadlibrary()
test_shellcode_rwx()