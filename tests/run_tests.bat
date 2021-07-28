@echo @off
@REM TODO 32 bits Python

curl -L "https://www.python.org/ftp/python/3.9.6/python-3.9.6-amd64.exe" --output "C:\users\WDAGUtilityAccount\Downloads\python-3.9.6-amd64.exe"
"C:\users\WDAGUtilityAccount\Downloads\python-3.9.6-amd64.exe" /quiet InstallAllUsers=1 PrependPath=1 TargetDir=C:\Python3

curl -L "https://www.python.org/ftp/python/2.7.18/python-2.7.18.amd64.msi" --output "C:\users\WDAGUtilityAccount\Downloads\python-2.7.18.amd64.msi"
"C:\users\WDAGUtilityAccount\Downloads\python-2.7.18.amd64.msi" /quiet InstallAllUsers=1 PrependPath=1 TargetDir=C:\Python2

curl -L https://github.com/git-for-windows/git/releases/download/v2.32.0.windows.2/Git-2.32.0.2-64-bit.exe --output "C:\users\WDAGUtilityAccount\Downloads\Git-2.32.0.2-64-bit.exe"
C:\users\WDAGUtilityAccount\Downloads\Git-2.32.0.2-64-bit.exe /VERYSILENT /SUPPRESSMSGBOXES

timeout /t 30 /nobreak >nul

Xcopy /E /I C:\Users\WDAGUtilityAccount\Desktop\pwintools C:\Users\WDAGUtilityAccount\Downloads\pwintools

SET PY2="C:\Python2\python.exe"
SET PY3="C:\Python3\python.exe"
SET WDIR=C:\Users\WDAGUtilityAccount\Downloads\pwintools
SET DBG2="C:\Users\WDAGUtilityAccount\Desktop\dbg2.log"
SET DBG3="C:\Users\WDAGUtilityAccount\Desktop\dbg3.log"
SET LOGFILE="C:\Users\WDAGUtilityAccount\Desktop\test.log"

REM install requirements python 3

%PY3% -m pip install lief >> %DBG3% 2>&1
pushd C:\Program Files\Git\cmd
%PY3% -m pip install -r %WDIR%\requirements.txt >> %DBG3% 2>&1
popd
pushd %WDIR%
%PY3% setup.py install >> %DBG3% 2>&1
popd

REM install requirements python 2

%PY2% -m pip install lief==0.9.0 >> %DBG2% 2>&1
pushd C:\Program Files\Git\cmd
%PY2% -m pip install -r %WDIR%\requirements.txt >> %DBG2% 2>&1
popd

pushd %WDIR%
%PY2% setup.py install >> %DBG2% 2>&1
popd

REM build test PE using python 2/3

pushd %WDIR%\tests

%PY2% build_pwn_pe.py
@REM %PY3% build_pwn_pe.py 

@REM Run tests
@echo "---- Python 2 tests ----" > %LOGFILE%
@CALL %WDIR%\tests\tests.bat %PY2% >> %LOGFILE% 2>&1

@echo "---- Python 3 tests ----" >> %LOGFILE%
@CALL %WDIR%\tests\tests.bat %PY3% >> %LOGFILE% 2>&1

popd

@C:\Windows\System32\notepad.exe %LOGFILE%