import os
import sys
print("--- Running Python {} ---".format(sys.version[0]))

try:
    import windows
except:
    print("FAIL PythonForWindows not installed")

try:
    import lief
except:
    print("FAIL lief not installed")

try:
    import pwintools
except:
    print("FAIL pwintools not installed")

try:
    open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pwn.exe"), 'r')
except:
    print("FAIL cannot find pwn.exe")