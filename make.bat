@echo off
setlocal

if "%~1"=="" goto :help

set "TARGET=%~1"
set "COMPOSE_FILE=%~2"
if "%COMPOSE_FILE%"=="" set "COMPOSE_FILE=docker-compose.yml"

where docker-compose >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  set "DC=docker-compose"
) else (
  set "DC=docker compose"
)

if /I "%TARGET%"=="build" goto :build
if /I "%TARGET%"=="run" goto :run
if /I "%TARGET%"=="docker-build" goto :docker_build
if /I "%TARGET%"=="docker-up" goto :docker_up
if /I "%TARGET%"=="docker-down" goto :docker_down
if /I "%TARGET%"=="restart" goto :restart
if /I "%TARGET%"=="test" goto :test
if /I "%TARGET%"=="macos-helper" goto :macos_only
if /I "%TARGET%"=="restart-helper" goto :macos_only
if /I "%TARGET%"=="restart-all" goto :macos_only

echo Unknown target: %TARGET%
goto :help

:build
go build -o bin/server.exe ./cmd/server
exit /b %ERRORLEVEL%

:run
go run ./cmd/server
exit /b %ERRORLEVEL%

:docker_build
docker build -t password-manager-go:local .
exit /b %ERRORLEVEL%

:docker_up
call :compose up --build
exit /b %ERRORLEVEL%

:docker_down
call :compose down
exit /b %ERRORLEVEL%

:restart
call :compose down || exit /b %ERRORLEVEL%
call :compose up --build
exit /b %ERRORLEVEL%

:test
go test ./...
exit /b %ERRORLEVEL%

:macos_only
echo Target "%TARGET%" is macOS-specific and not supported in Windows make.bat.
exit /b 1

:compose
if /I "%DC%"=="docker-compose" (
  docker-compose -f "%COMPOSE_FILE%" %*
) else (
  docker compose -f "%COMPOSE_FILE%" %*
)
exit /b %ERRORLEVEL%

:help
echo Usage:
echo   make.bat ^<target^> [compose_file]
echo.
echo Targets:
echo   build          Build server binary to .\bin\server.exe
echo   run            Run server locally with go run
echo   test           Run Go tests
echo   docker-build   Build Docker image password-manager-go:local
echo   docker-up      Start app + dependencies using Docker Compose
echo   docker-down    Stop Docker Compose services
echo   restart        Recreate Docker Compose services
echo.
echo Notes:
echo   - Optional second arg sets compose file. Default: docker-compose.yml
echo   - macos-helper, restart-helper, restart-all are macOS-only targets.
exit /b 1
