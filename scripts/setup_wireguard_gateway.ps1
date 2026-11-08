<#
.SYNOPSIS
    Configures Windows as a full-tunnel WireGuard VPN Gateway and NAT router.
.DESCRIPTION
    1. Enables IP routing (IPEnableRouter) in the Windows TCP/IP stack.
    2. Enables packet forwarding across active network interfaces.
    3. Provisions Windows NetNat for the WireGuard VPN client subnet (10.8.0.0/24).
    4. Opens Windows Defender Firewall port 51820/UDP for incoming tunnel traffic.
    5. Validates network health and gateway readiness.
.NOTES
    Must be executed in PowerShell as Administrator.
#>

param(
    [string]$VpnSubnet = "10.8.0.0/24",
    [int]$ListenPort = 51820,
    [string]$NatName = "WireGuardNAT"
)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   CONFIGURING WINDOWS WIREGUARD VPN GATEWAY & IP NAT ROUTING         " -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Require Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# 2. Enable IPEnableRouter in Registry
Write-Host "[1/5] Enabling Windows IP Stack Routing (IPEnableRouter)..." -ForegroundColor Yellow
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Set-ItemProperty -Path $regPath -Name "IPEnableRouter" -Value 1 -Type DWord
    Write-Host "      [+] IPEnableRouter set to 1 (Enabled)." -ForegroundColor Green
} catch {
    Write-Warning "      [!] Could not set IPEnableRouter: $_"
}

# 3. Enable IP Forwarding on Active Network Interfaces
Write-Host "[2/5] Enabling IP packet forwarding on active interfaces..." -ForegroundColor Yellow
try {
    Get-NetIPInterface | Where-Object { $_.ConnectionState -eq 'Connected' } | Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue
    Write-Host "      [+] Forwarding enabled on connected interfaces." -ForegroundColor Green
} catch {
    Write-Warning "      [!] NetIPInterface forwarding notice: $_"
}

# 4. Configure Windows NetNat for VPN Subnet
Write-Host "[3/5] Configuring Windows NetNat ($VpnSubnet)..." -ForegroundColor Yellow
try {
    $existingNat = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
    if ($existingNat) {
        Write-Host "      [*] NetNat '$NatName' already exists for prefix $($existingNat.InternalIPInterfaceAddressPrefix)." -ForegroundColor Green
    } else {
        New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $VpnSubnet | Out-Null
        Write-Host "      [+] Created NetNat '$NatName' for subnet $VpnSubnet." -ForegroundColor Green
    }
} catch {
    Write-Warning "      [!] NetNat configuration note: $_"
}

# 5. Open Windows Firewall Port 51820/UDP
Write-Host "[4/5] Opening Windows Firewall for WireGuard (UDP $ListenPort)..." -ForegroundColor Yellow
try {
    $ruleName = "WireGuardServerInbound"
    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Write-Host "      [*] Firewall rule '$ruleName' already active." -ForegroundColor Green
    } else {
        New-NetFirewallRule -Name $ruleName `
            -DisplayName "WireGuard VPN Server Endpoint (UDP $ListenPort)" `
            -Direction Inbound `
            -Protocol UDP `
            -LocalPort $ListenPort `
            -Action Allow | Out-Null
        Write-Host "      [+] Firewall rule created for UDP port $ListenPort." -ForegroundColor Green
    }
} catch {
    Write-Warning "      [!] Firewall rule note: $_"
}

# 6. Diagnostics & Verification
Write-Host "[5/5] Verifying Gateway Routing Status..." -ForegroundColor Yellow
$routingStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters").IPEnableRouter
Write-Host "      - IP Routing Enabled in Registry: $($routingStatus -eq 1)" -ForegroundColor White
$natRules = Get-NetNat -ErrorAction SilentlyContinue
if ($natRules) {
    foreach ($n in $natRules) {
        Write-Host "      - Active NAT: $($n.Name) -> Prefix: $($n.InternalIPInterfaceAddressPrefix)" -ForegroundColor White
    }
} else {
    Write-Host "      - NetNat: None" -ForegroundColor Yellow
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   GATEWAY SETUP COMPLETE. Windows will route decrypted client traffic." -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan

