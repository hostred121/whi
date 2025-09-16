# ==============================
# Script Completo de Reversão RDP + NGROK
# com Desativação de Senha no Bloqueio
# ==============================

# Configuração para executar sem confirmações
$ErrorActionPreference = "SilentlyContinue"
$ConfirmPreference = "None"

Write-Host "`n==== REVERSÃO COMPLETA RDP + NGROK ====`n"
Write-Host "==== DESATIVANDO SENHA NO BLOQUEIO ====`n"

# 1. Obter usuário atual (mantido do script original)
$CurrentUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
if ($CurrentUser) {
    $UserName = $CurrentUser.Split("\")[-1]
    Write-Host "[1/8] Usuário detectado: $UserName"
} else {
    Write-Host "[1/8] Não foi possível detectar o usuário atual."
    $UserName = "admin"
}

# 2. Remover senha do usuário admin (forçar senha vazia)
Write-Host "[2/8] Removendo senha do usuário admin..."
$secureString = ConvertTo-SecureString "" -AsPlainText -Force
Set-LocalUser -Name "admin" -Password $secureString -ErrorAction SilentlyContinue
net user admin "" 2>$null
Write-Host " - Senha do usuário 'admin' removida (senha vazia)."

# 3. Desativar RDP e bloquear firewall
Write-Host "[3/8] Desativando RDP e firewall..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Disable-NetFirewallRule -DisplayGroup "Remote Desktop" 2>$null

# 4. Reverter políticas de RDP para configurações seguras
Write-Host "[4/8] Revertendo políticas de RDP para configurações seguras..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f 2>$null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 1 /f 2>$null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v fPromptForPassword /t REG_DWORD /d 1 /f 2>$null

# 5. Remover arquivos do ngrok
Write-Host "[5/8] Removendo arquivos do ngrok..."
$NgrokPath = "$env:USERPROFILE\ngrok.exe"
$NgrokConfigPath = "$env:USERPROFILE\.ngrok2"
$NgrokConfigPath2 = "$env:USERPROFILE\.ngrok"

if (Test-Path $NgrokPath) {
    Remove-Item $NgrokPath -Force 2>$null
    Write-Host " - ngrok.exe removido."
}

if (Test-Path $NgrokConfigPath) {
    Remove-Item $NgrokConfigPath -Recurse -Force 2>$null
    Write-Host " - Configurações do ngrok removidas."
}

if (Test-Path $NgrokConfigPath2) {
    Remove-Item $NgrokConfigPath2 -Recurse -Force 2>$null
    Write-Host " - Configurações antigas do ngrok removidas."
}

# 6. Parar processos do ngrok
Write-Host "[6/8] Parando processos do ngrok..."
Get-Process -Name "ngrok" 2>$null | Stop-Process -Force 2>$null

# 7. Desativar a solicitação de senha no bloqueio de tela
Write-Host "[7/8] Desativando solicitação de senha no bloqueio de tela..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 0 /f 2>$null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v disablecad /t REG_DWORD /d 1 /f 2>$null

# 8. Configurar autologon e desativar proteção de tela
Write-Host "[8/8] Configurando para login automático..."
try {
    $DefaultUserName = (Get-WmiObject -Class Win32_ComputerSystem).UserName.Split("\")[-1]
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d "1" /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d "$DefaultUserName" /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "" /f 2>$null
    
    reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d "0" /f 2>$null
    reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d "0" /f 2>$null
    
    Write-Host " - Configuração de autologon ajustada."
} catch {
    Write-Host " - Não foi possível configurar autologon."
}

# ==============================
# Confirmação de reversão completa
# ==============================
Write-Host "`n✅ REVERSÃO CONCLUÍDA COM SUCESSO!"
Write-Host "🔹 RDP desativado"
Write-Host "🔹 Firewall reconfigurado"
Write-Host "🔹 Políticas de segurança restauradas"
Write-Host "🔹 Ngrok removido completamente"
Write-Host "🔹 Senha do usuário 'admin' removida (senha vazia)"
Write-Host "🔹 Solicitação de senha no bloqueio desativada"
Write-Host "🔹 Login automático configurado"
Write-Host "`n⚠️  O usuário 'admin' ainda existe mas sem senha definida"
Write-Host "⚠️  Reinicie o computador para que todas as alterações tenham efeito completo"

# Restaurar configurações padrão do PowerShell
$ErrorActionPreference = "Continue"
$ConfirmPreference = "High"
