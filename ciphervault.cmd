@echo off
rem CipherVault Launcher Wrapper
rem Garante que o PowerShell corre com permissoes de execucao corretas
title CipherVault v1.6.0

powershell -ExecutionPolicy Bypass -File "launcher\launcher.ps1"
if %errorlevel% neq 0 (
    echo.
    echo [ERRO] Ocorreu um erro critico ao iniciar o launcher.
    pause
)
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
