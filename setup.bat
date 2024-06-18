@echo off
if "%~1"=="" (
    echo Usage: %0 [subfolder]
    echo Please specify a subfolder path.
    pause
    exit /b
)

set "subfolder=%~1"
set "baseDir=%~dp0"
set "targetDir=%baseDir%\%subfolder%\.vscode"

if not exist "%baseDir%\%subfolder%\" (
    echo The specified subfolder does not exist in the base directory.
    pause
    exit /b
)

if exist "%targetDir%" (
    echo Folder "%targetDir%" already exists.
) else (
    mkdir "%targetDir%"
    echo .vscode folder created at "%targetDir%"
)

rem Create cmake-kits.json
echo Creating cmake-kits.json...
> "%targetDir%\cmake-kits.json" (
echo [
echo    {
echo     "name": "Zephyr build tool",
echo     "environmentVariables": {
echo         "ZEPHYR_BASE": "",
echo         "ZEPHYR_SDK_INSTALL_DIR": ""
echo     },
echo     "cmakeSettings": {
echo         "BOARD": "frdm_mcxn947/mcxn947/cpu0"
echo     },
echo     "keep": true
echo    }
echo ]
)
echo cmake-kits.json created.

rem Create cmake-variants.json
echo Creating cmake-variants.json...
> "%targetDir%\cmake-variants.json" (
echo {
echo     "build_type": {
echo         "default": "debug",
echo         "choices": {
echo             "debug": {
echo                 "short": "debug",
echo                 "buildType": "debug"
echo             },
echo             "release": {
echo                 "short": "release",
echo                 "buildType": "release"
echo             }
echo         }
echo     }
echo }
)
echo cmake-variants.json created.

rem Create launch.json
echo Creating launch.json...
> "%targetDir%\launch.json" (
echo {
echo     "configurations": [
echo         {
echo             "type": "cppdbg",
echo             "name": "Debug project configuration",
echo             "request": "launch",
echo             "cwd": "${workspaceRoot}",
echo             "MIMode": "gdb",
echo             "setupCommands": [
echo                 {"text": "set remotetimeout 600"},
echo                 {"text": "set debug-file-directory"}
echo             ],
echo             "program": "",
echo             "miDebuggerServerAddress": "",
echo             "variables": {
echo                 "mcuxStopAtSymbol": "main",
echo                 "mcuxSerialNumber": "",
echo                 "mcuxAttach": "false",
echo                 "mcuxRemoteProbeType": ""
echo             },
echo             "logging": {
echo                 "engineLogging": false
echo             }
echo         }
echo     ]
echo }
)
echo launch.json created.

rem Create mcuxpresso-tools.json
echo Creating mcuxpresso-tools.json...
> "%targetDir%\mcuxpresso-tools.json" (
echo {
echo     "version": "1.1",
echo     "toolchainPath": "",
echo     "toolchainVersion": "",
echo     "linkedProjects": [],
echo     "trustZoneType": "none",
echo     "multicoreType": "none",
echo     "debug": {
echo         "linkserver": {},
echo         "pemicro": {},
echo         "segger": {}
echo     },
echo     "projectType": "zephyr-workspace",
echo     "sdk": {
echo         "boardId": "frdm_mcxn947/mcxn947/cpu0",
echo         "version": "",
echo         "path": ""
echo     }
echo }
)
echo mcuxpresso-tools.json created.

rem Create settings.json
echo Creating settings.json...
> "%targetDir%\settings.json" (
echo {
echo     "cmake.configureOnOpen": false,
echo     "C_Cpp.errorSquiggles": "disabled",
echo     "cmake.preferredGenerators": [
echo         "Ninja",
echo         "Unix Makefiles",
echo         "MinGW Makefiles"
echo     ],
echo     "C_Cpp.default.configurationProvider": "ms-vscode.cmake-tools",
echo     "cmake.sourceDirectory": "${workspaceFolder}"
echo }
)
echo settings.json created.

pause
