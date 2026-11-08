@echo off
rem Lance Cockpit sans l'exe, avec Python. Il faut server.py, index.html et descriptions.json (dossier cockpit).
cd /d "%~dp0"
if exist "server.py" (set "DIR=%~dp0") else (set "DIR=%~dp0..\")
if not exist "%DIR%server.py" (
  echo server.py est introuvable. Placez ce fichier dans le dossier de Cockpit.
  pause
  exit /b 1
)
echo Cockpit tourne : fermez cette fenetre pour arreter.
where uv >nul 2>nul
if %errorlevel%==0 (
  uv run python -I "%DIR%server.py" %*
) else (
  where py >nul 2>nul
  if %errorlevel%==0 (
    py -3 -I "%DIR%server.py" %*
  ) else (
    echo Python n'est pas installe. Installez-le depuis python.org ou utilisez Cockpit.exe.
    pause
  )
)
