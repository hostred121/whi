# ==============================
# Script de Restauração RDP + Ngrok
# ==============================

Write-Host "`n==== Restaurando sistema ao estado original ====`n"

# 1. Desativar RDP
Write-Host "[1/5] Desativando RDP..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 1

# 2. Reativar NLA e segurança padrão
Write-Host "[2/5] Restaurando autenticação segura..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    /v UserAuthentication /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    /v SecurityLayer /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    /v fPromptForPassword /t REG_DWORD /d 1 /f

# 3. Remover usuário admin (se foi criado)
Write-Host "[3/5] Removendo usuário 'admin'..."
$CheckAdmin = net user admin 2>&1
if ($CheckAdmin -notmatch "O nome de utilizador não foi encontrado" -and
    $CheckAdmin -notmatch "The user name could not be found") {
    net user admin /delete
    Write-Host " - Usuário 'admin' removido."
} else {
    Write-Host " - Usuário 'admin' não existe, nada a remover."
}

# 4. Remover ngrok e configuração
Write-Host "[4/5] Removendo ngrok..."
$NgrokPath = "$env:USERPROFILE\ngrok.exe"
$NgrokConfig = "$env:LOCALAPPDATA\ngrok\ngrok.yml"
if (Test-Path $NgrokPath) { Remove-Item $NgrokPath -Force }
if (Test-Path $NgrokConfig) { Remove-Item $NgrokConfig -Force -ErrorAction SilentlyContinue }

# 5. Bloquear regras de firewall para RDP
Write-Host "[5/5] Bloqueando firewall para RDP..."
Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

Write-Host "`n✅ Restauração concluída!"
Write-Host "O sistema voltou ao estado original."
