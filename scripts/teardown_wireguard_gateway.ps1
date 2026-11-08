<#
.SYNOPSIS
    Tears down Windows WireGuard NAT and firewall rules safely.
.DESCRIPTION
    Reverts NetNat rule and removes inbound firewall rule. Does not disrupt
    the server's default internet route or physical network adapters.
.NOTES
    Must be executed in PowerShell as Administrator.
#>

param(
    [string]$NatName = "WireGuardNAT",
    [string]$RuleName = "WireGuardServerInbound"
)

Write-Host "Tearing down Windows WireGuard Gateway configuration..." -ForegroundColor Yellow

$existingNat = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
if ($existingNat) {
    Remove-NetNat -Name $NatName -Confirm:$false
    Write-Host "[+] Removed NetNat '$NatName'." -ForegroundColor Green
}

$existingRule = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
if ($existingRule) {
    Remove-NetFirewallRule -Name $RuleName
    Write-Host "[+] Removed Firewall rule '$RuleName'." -ForegroundColor Green
}

Write-Host "Teardown complete. Host internet connectivity intact." -ForegroundColor Green

