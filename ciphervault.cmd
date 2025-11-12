@echo off
setlocal

rem Janela dedicada do CipherVault
title CipherVault

rem Detectar Python do venv se existir
set "PYEXE=python"
if exist ".venv\Scripts\python.exe" (
  set "PYEXE=.venv\Scripts\python.exe"
)

echo ===== CipherVault (versao) =====
"%PYEXE%" src\main.py --version
echo.
echo Opcoes disponiveis:
"%PYEXE%" src\main.py --help
echo.
echo A iniciar modo interativo...
"%PYEXE%" src\main.py
echo.
echo (Prima qualquer tecla para fechar esta janela)
pause >nul

endlocal
