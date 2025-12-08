# Script Launcher Inteligente v1.6.0
# Orquestra a instalação, atualização e execução do CipherVault

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path "$ScriptDir\..").Path
$VenvPath = "$ProjectRoot\.venv"
$PythonExe = "$VenvPath\Scripts\python.exe"
$PipExe = "$VenvPath\Scripts\pip.exe"
$UpdaterScript = "$ProjectRoot\launcher\updater.py"
$MainScript = "$ProjectRoot\src\main.py"
$ReqFile = "$ProjectRoot\requirements.txt"

Write-Host "===== CipherVault Launcher v1.6.0 =====" -ForegroundColor Cyan

# 1. Bootstrapping: Verificar e Criar Ambiente Virtual
if (-not (Test-Path $VenvPath)) {
    Write-Host "[INIT] Primeira execução detetada. A configurar ambiente..." -ForegroundColor Yellow
    Write-Host "       Isto pode demorar alguns minutos."
    
    # Tentar encontrar python no sistema
    try {
        python -m venv $VenvPath
    } catch {
        Write-Error "Python não encontrado no PATH. Por favor instale Python 3.10+."
        exit 1
    }
    
    if (Test-Path $ReqFile) {
        Write-Host "[INIT] A instalar dependências..." -ForegroundColor Yellow
        & $PipExe install -r $ReqFile | Out-Null
    }
    Write-Host "[INIT] Ambiente configurado com sucesso." -ForegroundColor Green
}

# 2. Verificar Atualizações
if (Test-Path $UpdaterScript) {
    Write-Host "[CHECK] A verificar atualizações..." -ForegroundColor Gray
    try {
        & $PythonExe $UpdaterScript --check-only
        if ($LASTEXITCODE -eq 1) {
            Write-Host "[UPDATE] Nova versão encontrada! A iniciar atualização..." -ForegroundColor Magenta
            & $PythonExe $UpdaterScript --perform-update
            
            # Reinstalar dependências caso tenham mudado
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[UPDATE] A verificar novas dependências..."
                & $PipExe install -r $ReqFile | Out-Null
                Write-Host "[UPDATE] Sistema atualizado com sucesso." -ForegroundColor Green
            } else {
                Write-Host "[ERROR] Falha na atualização. A continuar com versão local." -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "[WARN] Não foi possível verificar atualizações (sem internet?)." -ForegroundColor DarkGray
    }
}

# 3. Executar Aplicação
Write-Host "[RUN] A iniciar CipherVault..." -ForegroundColor Cyan
Write-Host ""
& $PythonExe $MainScript
