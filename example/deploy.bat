@echo off
setlocal enabledelayedexpansion

:deploy_module
set "code=%~1"
set "server_url=http://localhost:8080/mgnt"

echo Deploying "%code%" to "%server_url%"...

REM Send the file with curl and capture the response
curl -X POST "%server_url%" -F "code=@%code%"