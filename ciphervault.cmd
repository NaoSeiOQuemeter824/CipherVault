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
echo Opcoes disponiveis (menu interativo mantem-se apos cada acao):
"%PYEXE%" src\main.py --help
echo.
echo Comandos extra:
echo   - Ver chave publica:      python src\main.py public-key
echo   - Contactos - listar:     python src\main.py contacts-list
echo   - Contactos - adicionar:  python src\main.py contacts-add --name "NOME" --pubkey "caminho\para\public.pem"
echo   - Contactos - apagar:     python src\main.py contacts-delete --name "NOME"
echo   - Verificar autenticidade: python src\main.py verify "ficheiro.cvault"
echo.
echo A iniciar modo interativo...
"%PYEXE%" src\main.py
echo.
echo (Prima qualquer tecla para fechar esta janela)
pause >nul

endlocal
