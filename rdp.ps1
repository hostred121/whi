# ==============================
# Script RDP + Ngrok (2025) - Adaptável
# ==============================

Write-Host "`n==== Configuração RDP + Ngrok ====`n"

# 1. Obter usuário atual
$CurrentUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
if ($CurrentUser) {
    $UserName = $CurrentUser.Split("\")[-1]
    Write-Host "[1/6] Usuário detectado: $UserName"
} else {
    Write-Host "[1/6] Não foi possível detectar o usuário atual."
    $UserName = "admin"
}

# 2. Garantir que existe usuário "admin" com senha fixa
Write-Host "[2/6] Ajustando usuário admin..."
$CheckAdmin = net user admin 2>&1
if ($CheckAdmin -match "O nome de utilizador não foi encontrado" -or
    $CheckAdmin -match "The user name could not be found") {
    net user admin 1234angola /add
    net localgroup Administrators admin /add
    Write-Host " - Usuário 'admin' criado com senha 1234angola."
} else {
    net user admin 1234angola
    Write-Host " - Senha do usuário 'admin' ajustada para 1234angola."
}

# 3. Ativar RDP e liberar firewall
Write-Host "[3/6] Ativando RDP e firewall..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

# 4. Forçar login direto (sem confirmação local)
Write-Host "[4/6] Ajustando políticas de RDP para aceitar conexão sem confirmação..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    /v UserAuthentication /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    /v SecurityLayer /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    /v fPromptForPassword /t REG_DWORD /d 0 /f

# 5. Instalar ngrok se não existir
$NgrokPath = "$env:USERPROFILE\ngrok.exe"
if (-Not (Test-Path $NgrokPath)) {
    Write-Host "[5/6] Baixando ngrok..."
    $NgrokUrl = "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip"
    $ZipPath = "$env:TEMP\ngrok.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $NgrokUrl -OutFile $ZipPath
    Expand-Archive $ZipPath -DestinationPath $env:USERPROFILE -Force
    Remove-Item $ZipPath
} else {
    Write-Host "[5/6] Ngrok já instalado."
}

# 6. Configurar authtoken e iniciar túnel
$NgrokToken = "2dLkPrpAINQdmbQCSCevHfx8veH_6JR2RFKvz4ZcNXQyby5Uf"
& $NgrokPath config add-authtoken $NgrokToken

Write-Host "`n==== Iniciando túnel ngrok (TCP 3389)... ====`n"
Write-Host "⚠️ Deixe esta janela aberta para manter a conexão ativa!"
Write-Host "Quando aparecer o link, copie e use no Remote Desktop."

& $NgrokPath tcp 3389

# ==============================
# Instruções finais
# ==============================
Write-Host "`n✅ Configuração concluída!"
Write-Host "Use estes dados no Remote Desktop (celular/PC):"
Write-Host "   🔹 Usuário: admin"
Write-Host "   🔹 Senha:   1234angola"
Write-Host "   🔹 Host:    (veja o link tcp gerado pelo ngrok)"
Write-Host "`nExemplo:"
Write-Host "   Host: 0.tcp.ngrok.io"
Write-Host "   Porta: <número_da_porta>"
Write-Host "   Usuário: admin"
Write-Host "   Senha:   1234angola"

