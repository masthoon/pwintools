@set PYTHON=%~1

REM 1. Requirements test
%PYTHON% %WDIR%\tests\test_requirements.py

REM 2. Network with no escaping
start cmd /C %PYTHON% %WDIR%\tests\simple_tcp_srv.py
@ping -n 1 127.0.0.1 >nul
echo YEAH| %PYTHON% %WDIR%\tests\test_remote.py

REM 2.bis Network with escaping
start cmd /C %PYTHON% %WDIR%\tests\simple_tcp_srv.py
@ping -n 1 127.0.0.1 >nul
echo YEAH| %PYTHON% %WDIR%\tests\test_remote.py 1

@REM 4. Simple process
%PYTHON% %WDIR%\tests\test_process.py

@REM 4.bis Simple process with IO
%PYTHON% %WDIR%\tests\test_process_io.py

@REM 4.final Simple process with interactive
echo InteractiveWorking|%PYTHON% %WDIR%\tests\test_process_interactive.py
echo InteractiveWorkingWithEscaping|%PYTHON% %WDIR%\tests\test_process_interactive.py 1

@REM 5. Shellcode
%PYTHON% %WDIR%\tests\test_shellcode.py

@REM 6. Exploit process with child interactive
%PYTHON% -c "print('dir\nexit')"|%PYTHON% %WDIR%\tests\test_pwn_pe.py

@REM TODO Remote timeout
@REM TODO Errors handling