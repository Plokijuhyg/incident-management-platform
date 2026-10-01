#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$EnableAuditPolicies, [switch]$StartApi)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$apiProject = Join-Path $projectRoot 'backend\IncidentPlatform.Api'

if ($EnableAuditPolicies) {
    $backupDirectory = Join-Path $projectRoot 'logs\backups'
    New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
    $backupFile = Join-Path $backupDirectory ('audit-policy-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.csv')
    & auditpol.exe /backup "/file:$backupFile"
    if ($LASTEXITCODE -ne 0) { throw 'Audit policy backup failed; no changes made.' }
    Write-Host "Audit policy backup: $backupFile"
    # Logon, User Account Management, Security Group Management.
    $subcategories = @(
        '{0CCE9215-69AE-11D9-BED3-505054503030}',
        '{0CCE9235-69AE-11D9-BED3-505054503030}',
        '{0CCE9237-69AE-11D9-BED3-505054503030}'
    )
    foreach ($subcategory in $subcategories) {
        & auditpol.exe /set "/subcategory:$subcategory" /success:enable /failure:enable
        if ($LASTEXITCODE -ne 0) { throw "Could not enable $subcategory. Previous changes remain; backup: $backupFile" }
        & auditpol.exe /get "/subcategory:$subcategory"
        if ($LASTEXITCODE -ne 0) { throw "Could not verify $subcategory." }
    }
}
# Verify read access without displaying sensitive event payloads.
$securityLog = Get-WinEvent -ListLog Security
$reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new('Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName)
try {
    $record = $reader.ReadEvent()
    if ($null -ne $record) { $record.Dispose() }
    Write-Host "Security channel readable. Enabled: $($securityLog.IsEnabled)."
} finally { $reader.Dispose() }

if ($StartApi) {
    & dotnet user-secrets set 'WindowsEvents:Enabled' 'true' --project $apiProject
    if ($LASTEXITCODE -ne 0) { throw 'Could not enable the Windows collector.' }
    $expectedExecutables = @(
        (Join-Path $apiProject 'bin\Debug\net10.0\IncidentPlatform.Api.exe'),
        (Join-Path $apiProject 'bin\Release\net10.0\IncidentPlatform.Api.exe')
    )
    $listeners = @(Get-NetTCPConnection -LocalPort 7146,5230 -State Listen -ErrorAction SilentlyContinue)
    $processesToStop = @()
    foreach ($listener in $listeners) {
        $running = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
        if ($running.ExecutablePath -notin $expectedExecutables) { throw "Port $($listener.LocalPort) is owned by another process. Nothing was stopped." }
        $processesToStop += $listener.OwningProcess
    }
    foreach ($processId in ($processesToStop | Sort-Object -Unique)) { Stop-Process -Id $processId }
    Write-Host 'Starting the local backend with this elevated Windows token. Keep this terminal open.'
    & dotnet run --project $apiProject --launch-profile https
} else {
    Write-Host 'Existing backend processes keep their original permissions. Use -StartApi to restart the local backend with this token.'
}
