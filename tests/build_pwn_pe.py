#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lief import PE
import windows.native_exec.simple_x86 as x86
from windows.generated_def import STD_OUTPUT_HANDLE, STD_INPUT_HANDLE

tobytes = lambda x:list(map(ord, x))
fmt_call = lambda addr: "[0x{:X}]".format(addr)
call_import = lambda addr: x86.mem(fmt_call(addr))

welcome   = "Welcome to the pwn challenge!\r\n\tLIEF is awesome\r\n"
test = "cmd.exe\0"

imports = {
    "kernel32.dll": {
        "GetStdHandle": 0,
        "WriteFile": 0,
        "ReadFile": 0,
        "WinExec": 0,
    },
}

data = {
    welcome: 0,
    test: 0,
}


binary32 = PE.Binary("pwn.exe", PE.PE_TYPE.PE32)

# Start with 0x100 bytes of \cc
section_text                 = PE.Section(".text")
section_text.content         = tobytes(x86.Int3().get_code() * 0x100)
section_text.virtual_address = 0x1000

# Init data section
data_raw = ''
for obj in data.keys():
    data[obj] = binary32.optional_header.imagebase + len(data_raw) + 0x2000
    data_raw += obj

section_data                 = PE.Section(".data")
section_data.content         = tobytes(data_raw)
section_data.virtual_address = 0x2000

section_text = binary32.add_section(section_text, PE.SECTION_TYPES.TEXT)
section_data = binary32.add_section(section_data, PE.SECTION_TYPES.DATA)

binary32.optional_header.addressof_entrypoint = section_text.virtual_address


for library in imports.keys():
    lib = binary32.add_library(library)
    for function in imports[library].keys():
        lib.add_entry(function)

for library in imports.keys():
    for function in imports[library].keys():
        imports[library][function] = binary32.predict_function_rva(library, function) + binary32.optional_header.imagebase


code = x86.MultipleInstr()
code += x86.Mov("EBP", "ESP")
code += x86.Sub("ESP", 0x100)
# GetStdHandle(STD_OUTPUT_HANDLE)
code += x86.Push(STD_OUTPUT_HANDLE)
code += x86.Call(call_import(imports["kernel32.dll"]["GetStdHandle"]))
# WriteFile(eax, welcome, len_welcome, &esp+8, 0)
code += x86.Lea("EDI", x86.mem("[ESP + 0x8]"))
code += x86.Push(0)
code += x86.Push("EDI")
code += x86.Push(len(welcome))
code += x86.Push(data[welcome])
code += x86.Push("EAX") # hConsoleOutput
code += x86.Call(call_import(imports["kernel32.dll"]["WriteFile"]))
# GetStdHandle(STD_INPUT_HANDLE)
code += x86.Push(STD_INPUT_HANDLE)
code += x86.Call(call_import(imports["kernel32.dll"]["GetStdHandle"]))
# ReadFile(eax, &esp+80, 0x50, &esp+8, 0)
code += x86.Lea("EBX", x86.mem("[ESP + 0x80]"))
code += x86.Push(0)
code += x86.Push("EDI")
code += x86.Push(0xF0)
code += x86.Push("EBX")
code += x86.Push("EAX") # hConsoleInput
code += x86.Call(call_import(imports["kernel32.dll"]["ReadFile"]))
# GetStdHandle(STD_OUTPUT_HANDLE)
code += x86.Push(STD_OUTPUT_HANDLE)
code += x86.Call(call_import(imports["kernel32.dll"]["GetStdHandle"]))
# WriteFile(eax, &esp+50, 0x50, &esp+8, 0)
code += x86.Push(0)
code += x86.Push("EDI")
code += x86.Push(0x50)
code += x86.Push("EBX")
code += x86.Push("EAX") # hConsoleOutput
code += x86.Call(call_import(imports["kernel32.dll"]["WriteFile"]))
code += x86.Mov("ESP", "EBP")
code += x86.Ret()


padded_code = code.get_code()
padded_code += x86.Nop().get_code() * (0x100 - len(padded_code))
section_text.content = tobytes(padded_code)


builder = PE.Builder(binary32)
builder.build_imports(True)
builder.build()
builder.write("pwn.exe")

print("Generated pwn.exe")