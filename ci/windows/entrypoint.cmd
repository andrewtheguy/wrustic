@echo off
rem Put link.exe, the CRT headers and the Windows SDK libraries on
rem PATH/INCLUDE/LIB before handing over to the real command.
rem
rem rustc can usually find a Visual Studio install on its own through the setup
rem configuration COM API, but that is a discovery heuristic and this is a
rem single-purpose image: setting the environment outright means a link failure
rem here is a real link failure, not a lookup that went sideways.
call "C:\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo entrypoint: vcvars64.bat failed 1>&2
    exit /b 1
)

rem Here rather than in an ENV line, so it extends the PATH the container
rem actually has instead of replacing it. See the Dockerfile for why.
set "PATH=C:\cargo\bin;%PATH%"

if "%~1" == "" (
    echo entrypoint: no command given 1>&2
    exit /b 2
)

%*
