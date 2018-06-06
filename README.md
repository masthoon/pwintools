# PWiNTOOLS

PWiNTOOLS is a very basic implementation of [pwntools][PWNTOOLS] for Windows to play with local processes and remote sockets.

Windows is not yet supported in the official [pwntools][PWNTOOLS]: [Minimal support for Windows #996](https://github.com/Gallopsled/pwntools/pull/996).

Feel free to contribute or reports bugs.

# Usage / Documentation

Read the [code][CODE] :)

The [tests][EXAMPLE] provides some examples of usage.


```python
from pwintools import *

DEBUG = True
if DEBUG:
	r = Process("chall.exe") # Spawn chall.exe process
	r.spawndebugger(breakin=False)
	log.info("Shellcode should be calling WinExec at 0x{:x}".format(r.get_remote_func_addr('kernel32.dll', 'WinExec')))
else:
	r = Remote("challenge.remote.service", 8080)

r.sendline('ID123456789') # send / write
if r.recvline().strip() == 'GOOD': # recv / read / recvn / recvall / recvuntil
	log.success('Woot password accepted!')
	r.send(shellcraft.amd64.WinExec('cmd.exe'))
else:
	log.failure('Bad password')

log.info('Starting interactive mode ...')
r.interactive() # interactive2 for Remote available
```

# Deps

[PythonForWindows][PYTHONFORWINDOWS] providing a Python implementation to play with Windows.

Optionals:
- [capstone][CAPSTONE]
- [keystone][KEYSTONE]

# TODO

```
	Improve 32 bits support and testing
	Support local Context like pwntools
	Improve Shellcraft to avoid NULL bytes (xor_pair)
	Provide examples with Python Debugger
	Integrate gadgets tool support (rp++)
	Process mitigation (appcontainer / Force ASLR rebase / Job sandboxing ...)
	`Port` the project to pwntools
```

[CODE]: https://github.com/masthoon/pwintools/blob/master/pwintools.py
[PWNTOOLS]: https://github.com/Gallopsled/pwntools
[PYTHONFORWINDOWS]: https://github.com/hakril/PythonForWindows
[CAPSTONE]: https://www.capstone-engine.org/
[KEYSTONE]: https://www.keystone-engine.org/
[EXAMPLE]: https://github.com/masthoon/pwintools/tree/master/tests
