import os
import sys
import time
import ctypes
import msvcrt
import random
import string
import struct
import socket
import logging
import threading

import windows
import windows.winobject
import windows.winproxy
import windows.native_exec.nativeutils
import windows.generated_def as gdef
from windows.generated_def.winstructs import *
import windows.native_exec.simple_x64 as x64


try:
    import capstone
    def disasm(data, bitness = 64, vma = 0):
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if bitness == 64 else capstone.CS_MODE_32)
        dis = ''
        for i in cs.disasm(data, vma):
            dis += "%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str)
        return dis
except ImportError:
    def disasm(data, bitness = 64, vma = 0):
        raise(NotImplementedError("Capstone module not found"))

try:
    import keystone
    def asm(code, bitness = 64, vma = 0):
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64 if bitness == 64 else keystone.KS_MODE_32)
        encoding, count = ks.asm(code, vma)
        return encoding
except ImportError:
    def asm(code, bitness = 64, vma = 0):
        raise(NotImplementedError("Keystone module not found"))

alpha = string.ascii_letters
alpha_lower = string.ascii_lowercase
alpha_upper = string.ascii_uppercase
digits = string.digits
all_chars = string.ascii_letters+string.digits+' '+string.punctuation
printable = string.printable
all256 = ''.join([chr(i) for i in xrange(256)])

class DotDict(dict):
    """Allow access to dict elements using dot"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def xor_pair(data, avoid = '\x00\n'):
    """xor_pair(data, avoid = '\\x00\\n') -> None or (str, str)
    Finds two strings that will xor into a given string, while only
    using a given alphabet.
    Arguments:
        data (str): The desired string.
        avoid: The list of disallowed characters. Defaults to nulls and newlines.
    Returns:
        Two strings which will xor to the given string. If no such two strings exist, then None is returned.
    Example:
        >>> xor_pair("test")
        ('\\x01\\x01\\x01\\x01', 'udru')
    """
    alphabet = list(chr(n) for n in range(256) if chr(n) not in avoid)
    res1 = ''
    res2 = ''
    for c1 in data:
        for c2 in alphabet:
            c3 = chr(ord(c1) ^ ord(c2))
            if c3 in alphabet:
                res1 += c2
                res2 += c3
                break
        else:
            return None
    return res1, res2

def xor(s1,s2):
    """xor(s1,s2) -> str
    Xor string using ASCII values.
    Examples:
        >>> xor('test','beef')
        '\x16\x00\x16\x12'
    """
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

def bruteforce(charset, min_len=1, max_len=8):
    """bruteforce(charset, min_len=1, max_len=8) -> itertools.chain
    Yield a generator for bruteforce in charset.
    Example:
      >>> bruteforce(digits, 1, 2)
      <itertools.chain>
    Use: for elem in bruteforce(digits, 1, 2): [...]
    Charsets: alpha, alpha_lower, alpha_upper, digits, printable, all256
    """
    import itertools
    return itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(min_len, max_len + 1))

def cut(s, n):
    """cut(s, n) -> list
    Cut the s string every n characters.
    Example:
      >>> cut('020304', 2)
      ['02', '03', '04']
    """
    return [s[i:i+n] for i in range(0, len(s), n)]

def ordlist(s):
    """ordlist(s) -> list
    Turns a string into a list of the corresponding ascii values.
    Example:
      >>> ordlist("hello")
      [104, 101, 108, 108, 111]
    """
    return map(ord, s)

def unordlist(cs):
    """unordlist(cs) -> str
    Takes a list of ascii values and returns the corresponding string.
    Example:
      >>> unordlist([104, 101, 108, 108, 111])
      'hello'
    """
    return ''.join(chr(c) for c in cs)

def rand(min=0, max=10000):
    """rand(min=0, max=10000) -> int
    Randomly select of a int between min and max.
    """
    return random.randint(min, max)

def randstr(length=8, charset=all_chars):
    """randstr(length=8, charset=all_chars) -> str
    Randomly select (length) chars from the charset.
    """
    return ''.join(random.choice(charset) for _ in range(length))

def hexdump(src, length=16):
    """hexdump(src, length=16) -> str
    From a binary src returns the hexdump aligned on length (16)
    """
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

def p64(i):
    """p64(i) -> str
    Pack 64 bits integer (little endian)
    """
    return struct.pack('<q', i)

def u64(s):
    """u64(s) -> int
    Unpack 64 bits integer from a little endian str representation
    """
    return struct.unpack('<q', s)[0]

def p32(i):
    """p32(i) -> str
    Pack 32 bits integer (little endian)
    """
    return struct.pack('<i', i)

def u32(s):
    """u32(s) -> int
    Unpack 32 bits integer from a little endian str representation
    """
    return struct.unpack('<i', s)[0]
    
def p16(i):
    """p16(i) -> str
    Pack 16 bits integer (little endian)
    """
    return struct.pack('<h', i)

def u16(s):
    """u16(s) -> int
    Unpack 16 bits integer from a little endian str representation
    """
    return struct.unpack('<h', s)[0]

CreatePipePrototype = gdef.WINFUNCTYPE(gdef.BOOL, gdef.PHANDLE, gdef.PHANDLE, gdef.LPSECURITY_ATTRIBUTES, gdef.DWORD)
CreatePipeParams = ((1, 'hReadPipe'), (1, 'hReadPipe'), (1, 'lpPipeAttributes'), (1, 'nSize'))

@windows.winproxy.Kernel32Proxy('CreatePipe', deffunc_module=sys.modules[__name__])
def CreatePipe(lpPipeAttributes=None, nSize=0):
    hReadPipe = gdef.HANDLE()
    hWritePipe = gdef.HANDLE()
    CreatePipe.ctypes_function(hReadPipe, hWritePipe, lpPipeAttributes, nSize)
    return hReadPipe.value, hWritePipe.value

PeekNamedPipePrototype = gdef.WINFUNCTYPE(gdef.BOOL, gdef.HANDLE, gdef.LPVOID, gdef.DWORD, gdef.LPDWORD, gdef.LPDWORD, gdef.LPDWORD)
PeekNamedPipeParams = ((1, 'hNamedPipe'), (1, 'lpBuffer'), (1, 'nBufferSize'), (1, 'lpBytesRead'), (1, 'lpTotalBytesAvail'), (1, 'lpBytesLeftThisMessage'))

@windows.winproxy.Kernel32Proxy('PeekNamedPipe', deffunc_module=sys.modules[__name__])
def PeekNamedPipe(hNamedPipe):
    lpTotalBytesAvail = gdef.DWORD()
    PeekNamedPipe.ctypes_function(hNamedPipe, None, 0, None, lpTotalBytesAvail, None)
    return lpTotalBytesAvail.value


_msgtype_prefixes = {
    'status'       : 'x',
    'success'      : '+',
    'failure'      : '-',
    'debug'        : 'DEBUG',
    'info'         : '*',
    'warning'      : '!',
    'error'        : 'ERROR',
    'exception'    : 'ERROR',
    'critical'     : 'CRITICAL'
}

class MiniLogger(object):
    """Python simple logger implementation"""
    def __init__(self):
        self.logger = logging.getLogger("mini")
        streamHandler = logging.StreamHandler()
        formatter = logging.Formatter('%(message)s')
        streamHandler.setFormatter(formatter)
        self.logger.addHandler(streamHandler)
        self.log_level = 'info'
        
    def get_log_level(self):
        return self._log_level

    def set_log_level(self, log_level):
        self._log_level = log_level
        if isinstance(log_level, int):
            self.logger.setLevel(log_level)
        else:
            self.logger.setLevel(logging._levelNames[log_level.upper()])

    log_level = property(get_log_level, set_log_level)
    
    def success(self, message, *args, **kwargs):
        self._log(logging.INFO, message, args, kwargs, 'success')

    def failure(self, message, *args, **kwargs):
        self._log(logging.INFO, message, args, kwargs, 'failure')
        
    def debug(self, message, *args, **kwargs):
        self._log(logging.DEBUG, message, args, kwargs, 'debug')

    def info(self, message, *args, **kwargs):
        self._log(logging.INFO, message, args, kwargs, 'info')

    def warning(self, message, *args, **kwargs):
        self._log(logging.WARNING, message, args, kwargs, 'warning')

    def error(self, message, *args, **kwargs):
        self._log(logging.ERROR, message, args, kwargs, 'error')
        raise Exception(message % args)

    def exception(self, message, *args, **kwargs):
        kwargs["exc_info"] = 1
        self._log(logging.ERROR, message, args, kwargs, 'exception')
        raise

    def critical(self, message, *args, **kwargs):
        self._log(logging.CRITICAL, message, args, kwargs, 'critical')

    def log(self, level, message, *args, **kwargs):
        self._log(level, message, args, kwargs, None)
        
    def _log(self, level, msg, args, kwargs, msgtype):
        if msgtype:
            msg = '[%s] %s' % (_msgtype_prefixes[msgtype], str(msg))
        self.logger.log(level, msg, *args, **kwargs)


def interact(obj, escape = False):
    """Base standard input/ouput interaction with a pipe/socket stolen from pwntools"""
    go = threading.Event()
    go.clear()
    def recv_thread():
        while not go.is_set():
            cur = obj.recvall(timeout = 200)
            cur = cur.replace('\r\n', '\n')
            if escape:
                cur = cur.encode('string-escape')
                cur = cur.replace('\\n', '\n')
                cur = cur.replace('\\t', '\t')
                cur = cur.replace('\\\\', '\\')
            if cur:
                sys.stdout.write(cur)
                if escape and not cur.endswith('\n'):
                    sys.stdout.write('\n')
                sys.stdout.flush()
            go.wait(0.2)

    t = threading.Thread(target = recv_thread)
    t.daemon = True
    t.start()
    try:
        while not go.is_set():
            # Impossible to timeout readline
            # Wait a little and check obj
            go.wait(0.2)
            try:
                obj.check_closed()
                data = sys.stdin.readline() 
                if data:
                    obj.send(data)
                else:
                    go.set()
            except EOFError:
                go.set()
    except KeyboardInterrupt:
        go.set()
        
    while t.is_alive():
        t.join(timeout = 0.1)

class Pipe(object):
    """Windows pipe support"""
    def __init__(self, bInheritHandle = 1):
        attr = SECURITY_ATTRIBUTES()
        attr.lpSecurityDescriptor = 0
        attr.bInheritHandle = bInheritHandle
        attr.nLength = ctypes.sizeof(attr)
        self._rpipe, self._wpipe = CreatePipe(attr)
        self.timeout = 500 # ms
        self.tick = 40 # ms
        
    def get_handle(self, mode = 'r'):
        if mode and mode[0] == 'w':
            return self._wpipe
        return self._rpipe
        
    def __del__(self):
        windows.winproxy.CloseHandle(self._rpipe)
        windows.winproxy.CloseHandle(self._wpipe)
    
    def select(self):
        return PeekNamedPipe(self._rpipe)
        
    def _read(self, size):
        if size == 0:
            return ''
        buffer = ctypes.create_string_buffer(size)
        windows.winproxy.ReadFile(self._rpipe, buffer)
        return buffer.raw
        
    def read(self, size):
        if self.select() < size:
            elapsed = 0
            while elapsed <= self.timeout and self.select() < size:
                time.sleep(float(self.tick) / 1000)
                elapsed += self.tick
        return self._read(min(self.select(), size))
    
    def write(self, buffer):
        windows.winproxy.WriteFile(self._wpipe, buffer)

class Remote(object):
    """
        Wrapper for remote connections
            Remote("127.0.0.1", 8888)
    """
    def __init__(self, ip, port, family = socket.AF_INET, type = socket.SOCK_STREAM):
        self.sock = socket.socket(family, type)
        self.ip = ip
        self.port = port
        self.timeout = 500 # ms
        self._default_timeout = 500 # ms
        try:
            self.sock.connect((ip, port))
        except socket.timeout:
            self._closed = True
            log.error("EOFError: Socket {:s} connection failed".format(self))
            
        self._closed = False
        self.newline = '\n'
    
    def __repr__(self):
        return '<{0} "{1}:{2}" at {3}>'.format(self.__class__.__name__, self.ip, self.port, hex(id(self)))
    
    def close(self):
        self.sock.close()
        self._closed = True
        
    def check_closed(self, force_exception = True):
        if self._closed and force_exception:
            raise(EOFError("Socket {:s} closed".format(self)))
        elif self._closed:
            log.warning("EOFError: Socket {:s} closed".format(self))
        return self._closed
    
    def get_timeout(self):
        return self._timeout

    def set_timeout(self, timeout):
        if timeout:
            self._timeout = timeout
            self.sock.settimeout(float(timeout) / 1000)
        elif self._timeout != self._default_timeout:
            self.timeout = self._default_timeout
            
    timeout = property(get_timeout, set_timeout)
    
    def read(self, n, timeout = None, no_warning = False):
        self.timeout = timeout
        buf = ''
        if not self.check_closed(False):
            try:
                buf = self.sock.recv(n)
            except socket.timeout:
                if not no_warning:
                    log.warning("EOFError: Timeout {:s} - Incomplete read".format(self))
            except socket.error:
                self._closed = True
                if not no_warning:
                    log.warning("EOFError: Socket {:s} closed".format(self))
        return buf
    
    def write(self, buf):
        if not self.check_closed(True):
            try:
                return self.sock.send(buf)
            except socket.error:
                self._closed = True
                log.warning("EOFError: Socket {:s} closed".format(self))
            
    def send(self, buf):
        self.write(buf)
        
    def sendline(self, line):
        self.write(line + self.newline)
        
    def recv(self, n, timeout = None):
        return self.read(n, timeout)
    
    def recvn(self, n, timeout = None):
        buf = self.read(n, timeout)
        if len(buf) != n:
            raise(EOFError("Timeout {:s} - Incomplete read".format(self)))
        return buf
    
    def recvall(self, force_exception = False, timeout = None):
        return self.read(0x100000, timeout, no_warning = True)
        
    def recvuntil(self, delim, timeout = None):
        buf = ''
        while delim not in buf:
            buf += self.recvn(1, timeout)
        return buf
        
    def recvline(self, timeout = None):
        return self.recvuntil(self.newline, timeout)
            
    def interactive(self, escape = False):
        interact(self, escape)
        
    def interactive2(self):
        """Interact with telnetlib"""
        fs = self.sock._sock
        import telnetlib
        t = telnetlib.Telnet()
        t.sock = fs
        t.interact()

class Process(windows.winobject.process.WinProcess):
    """
        Wrapper for Windows process
            Process(r"C:\Windows\system32\mspaint.exe")
            Process("pwn.exe", CREATE_SUSPENDED)
            Process([r"C:\Windows\system32\cmd.exe", '-c', 'echo', 'test'])
    """
    def __init__(self, cmdline, flags = 0, nostdhandles = False):
        self.cmd = cmdline
        self.flags = flags
        self.stdhandles = not nostdhandles
        self.debuggerpath = r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe'
        self.newline = '\n'
        
        if self.stdhandles:
            self.stdin = Pipe()
            self.stdout = Pipe()
            # stderr mixed with stdout self.stderr = Pipe()
            self.timeout = 500 # ms
            self._default_timeout = 500 # ms
        
        if self._create_process() != 0:
            raise(ValueError("CreateProcess failed - Invalid arguments"))
        super(Process, self).__init__(pid=self.__pid, handle=self.__phandle)
        if not (flags & CREATE_SUSPENDED):
            self.wait_initialized()
    
    def check_initialized(self):
        is_init = False
        try: # Accessing PEB
            self.peb.modules[1]
            is_init = True
        except:
            pass
        if not is_init:
            log.info("Process {:s} not initialized ...".format(self))
        return is_init
    
    def wait_initialized(self):
        while not self.check_initialized():
            time.sleep(0.05)
                
    def __del__(self):
        if self.__pid and not self.is_exit:
            self.exit(0)
    
    def _create_process(self):
        proc_info = PROCESS_INFORMATION()
        lpStartupInfo = None
        StartupInfo = STARTUPINFOA()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        if self.stdhandles:
            StartupInfo.dwFlags = gdef.STARTF_USESTDHANDLES
            StartupInfo.hStdInput = self.stdin.get_handle('r')
            StartupInfo.hStdOutput = self.stdout.get_handle('w')
            StartupInfo.hStdError = self.stdout.get_handle('w')
        lpStartupInfo = ctypes.byref(StartupInfo)
        lpCommandLine = None
        lpApplicationName = self.cmd
        if isinstance(self.cmd, (list,)):
            lpCommandLine = (" ".join([str(a) for a in self.cmd]))
            lpApplicationName = None
        try:
            windows.winproxy.CreateProcessA(lpApplicationName, lpCommandLine=lpCommandLine, bInheritHandles=True, dwCreationFlags=self.flags, lpProcessInformation=ctypes.byref(proc_info), lpStartupInfo=lpStartupInfo)
            windows.winproxy.CloseHandle(proc_info.hThread)
            self.__pid = proc_info.dwProcessId
            self.__phandle = proc_info.hProcess
        except Exception:
            self.__pid = None
            self.__phandle = None
            log.warning("Process {:s} failed to start!".format(self.cmd))
            return -1
        return 0
    
    def check_exit(self, raise_exc=False):
        if self.is_exit:
            if raise_exc:
                raise(EOFError("Process {:s} exited".format(self)))
            else:
                log.warning("Process {:s} exited".format(self))
    
    def check_closed(self):
        self.check_exit(True)
    
    def get_timeout(self):
        if self.stdhandles:
            return self._timeout
        return -1

    def set_timeout(self, timeout):
        if timeout:
            self._timeout = timeout
            if self.stdhandles:
                self.stdin.timeout = timeout
                self.stdout.timeout = timeout
        elif self._timeout != self._default_timeout:
            self.timeout = self._default_timeout

    timeout = property(get_timeout, set_timeout)
    
    def read(self, n, timeout = None, no_warning = False):
        self.timeout = timeout
        buf = ''
        if self.stdhandles and not self.check_exit():
            buf = self.stdout.read(n)
            if not no_warning and len(buf) != n:
                log.warning("EOFError: Timeout {:s} - Incomplete read".format(self))
        return buf
    
    def write(self, buf):
        if self.stdhandles and not self.check_exit(True):
            return self.stdin.write(buf)
            
    def send(self, buf):
        self.write(buf)
        
    def sendline(self, line):
        self.write(line + self.newline)
        
    def recv(self, n, timeout = None):
        return self.read(n, timeout)
    
    def recvn(self, n, timeout = None):
        buf = self.read(n, timeout)
        if len(buf) != n:
            raise(EOFError("Timeout {:s} - Incomplete read".format(self)))
        return buf
    
    def recvall(self, force_exception = False, timeout = None):
        return self.read(0x100000, timeout, no_warning = True)
        
    def recvuntil(self, delim, timeout = None):
        buf = ''
        while delim not in buf:
            buf += self.recvn(1, timeout)
        return buf
        
    def recvline(self, timeout = None):
        return self.recvuntil(self.newline, timeout)
            
    def interactive(self, escape = False):
        interact(self, escape)

    def leak(self, addr, count = 1):
        if not self.check_initialized():
            return ''
        try:
            return self.read_memory(addr, count)
        except Exception as e:
            log.warning("{}: {:s} {}".format(e.__class__.__name__, self, str(e)))
            return ''

    def search_memory(self, pattern):
        if not self.check_initialized():
            return 0
        for module in self.peb.modules:
            try:
                for section in module.pe.sections:
                    for page in xrange(section.start, section.start + section.size, 0x1000):
                        try:
                            pos = self.read_memory(page, min(0x1000, (section.start + section.size) - page)).find(pattern)
                            if pos != -1:
                                return page + pos
                        except:
                            pass
            except:
                pass
        return 0
        
    def get_import(self, dll_name, func_name):
        if not self.check_initialized():
            return 0
        pe = self.peb.modules[0].pe
        if dll_name in pe.imports:
            for imp in pe.imports[dll_name]:
                if imp.name == func_name:
                    return imp.addr
        return 0
        
    def get_remote_func_addr(self, dll_name, func_name):
        if not self.check_initialized():
            return 0
        name_modules = [m for m in self.peb.modules if m.name == dll_name]
        if not len(name_modules):
            return 0
        mod = name_modules[0]
        if not func_name in mod.pe.exports:
            return 0
        return mod.pe.exports[func_name]
        
    def libs(self,fullname=False):
        if not self.check_initialized():
            return 0
        if fullname:
            return {mod.fullname: mod.baseaddr for mod in self.peb.modules}
        return {mod.name: mod.baseaddr for mod in self.peb.modules}
    
    def close(self):
        if not self.is_exit:
            self.exit(0)
        
    def spawndebugger(self, breakin = True, cmd = None):
        cmd = [self.debuggerpath, '-p', str(self.pid)]
        if not breakin:
            cmd.append('-g')
        if cmd!=None:
            cmd.append('-c "%s"' % (cmd))	
        self.debugger = Process(cmd, nostdhandles=True)
        # Give time to the debugger
        time.sleep(1)

# https://github.com/hakril/PythonForWindows/blob/master/windows/native_exec/nativeutils.py
# https://github.com/hakril/PythonForWindows/blob/master/samples/native_utils.py

def sc_64_pushstr(s):
    if not s.endswith('\0'):
        s += '\0\0'
    PushStr_sc = x64.MultipleInstr()
    # TODO Use xor_pair to avoid NULL
    for block in cut(s, 8)[::-1]:
        block += '\0' * (8 - len(block))
        PushStr_sc += x64.Mov("RAX", u64(block))
        PushStr_sc += x64.Push("RAX")
    return PushStr_sc

def sc_64_WinExec(exe):
    dll = "KERNEL32.DLL\x00".encode("utf-16-le")
    api = "WinExec\x00"
    WinExec64_sc = x64.MultipleInstr()
    map(WinExec64_sc.__iadd__, [
        shellcraft.amd64.pushstr(dll),
        x64.Mov("RCX", "RSP"),
        shellcraft.amd64.pushstr(api),
        x64.Mov("RDX", "RSP"),
        x64.Call(":FUNC_GETPROCADDRESS64"),
        x64.Mov("R10", "RAX"),
        shellcraft.amd64.pushstr(exe),
        x64.Mov("RCX", "RSP"),
        x64.Sub("RSP", 0x30),
        x64.And("RSP", -32),
        x64.Call("R10"),
        x64.Label(":HERE"),
        x64.Jmp(":HERE"), # Dirty infinite loop
        # x64.Ret(),
        windows.native_exec.nativeutils.GetProcAddress64,
    ])
    return WinExec64_sc.get_code()



def sc_64_LoadLibrary(dll_path):
    dll = "KERNEL32.DLL\x00".encode("utf-16-le")
    api = "LoadLibraryA\x00"
    LoadLibrary64_sc = x64.MultipleInstr()
    map(LoadLibrary64_sc.__iadd__, [
        shellcraft.amd64.pushstr(dll),
        x64.Mov("RCX", "RSP"),
        shellcraft.amd64.pushstr(api),
        x64.Mov("RDX", "RSP"),
        x64.Call(":FUNC_GETPROCADDRESS64"),
        x64.Mov("R10", "RAX"),
        shellcraft.amd64.pushstr(dll_path),
        x64.Mov("RCX", "RSP"),
        x64.Sub("RSP", 0x30),
        x64.And("RSP", -32),
        x64.Call("R10"),
        x64.Label(":HERE"),
        x64.Jmp(":HERE"), # Dirty infinite loop
        # x64.Ret(),
        windows.native_exec.nativeutils.GetProcAddress64,
    ])
    return LoadLibrary64_sc.get_code()


def sc_64_AllocRWX(address, rwx_qword):
    dll = "KERNEL32.DLL\x00".encode("utf-16-le")
    api = "VirtualAlloc\x00"
    AllocRWX64_sc = x64.MultipleInstr()
    map(AllocRWX64_sc.__iadd__, [
        shellcraft.amd64.pushstr(dll),
        x64.Mov("RCX", "RSP"),
        shellcraft.amd64.pushstr(api),
        x64.Mov("RDX", "RSP"),
        x64.Call(":FUNC_GETPROCADDRESS64"),
        x64.Mov("R10", "RAX"),
        x64.Mov("RCX", address),
        x64.Mov("RDX", 0x1000),
        x64.Mov("R8", MEM_COMMIT | MEM_RESERVE),
        x64.Mov("R9", PAGE_EXECUTE_READWRITE),
        x64.Sub("RSP", 0x30),
        x64.And("RSP", -32),
        x64.Call("R10"),
        x64.Mov('RAX', rwx_qword),
        x64.Mov("RCX", address),
        x64.Mov(x64.mem('[RCX]'), 'RAX'),
        x64.Call("RCX"),
        windows.native_exec.nativeutils.GetProcAddress64,
    ])
    return AllocRWX64_sc.get_code()


log = MiniLogger()

shellcraft = DotDict()
shellcraft.amd64 = DotDict()
shellcraft.amd64.pushstr = sc_64_pushstr
shellcraft.amd64.WinExec = sc_64_WinExec
shellcraft.amd64.LoadLibrary = sc_64_LoadLibrary
shellcraft.amd64.AllocRWX = sc_64_AllocRWX