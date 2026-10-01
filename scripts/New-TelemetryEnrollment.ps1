#Requires -Version 5.1
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$TargetId,
 [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$')][string]$ComputerName,
 [Parameter(Mandatory=$true)][Uri]$Endpoint
)
$ErrorActionPreference='Stop'
if ($Endpoint.Scheme -ne 'https' -or $Endpoint.AbsolutePath -ne '/api/telemetry/events' -or $Endpoint.UserInfo -or $Endpoint.Query -or $Endpoint.Fragment) { throw 'Supply an exact HTTPS telemetry endpoint.' }
$repo=Split-Path -Parent $PSScriptRoot
$secretsPath=Join-Path $env:APPDATA 'Microsoft\UserSecrets\edfc24f8-0481-4fa1-96fc-bfc42f8cc29d\secrets.json'
$settings=Get-Content -LiteralPath $secretsPath -Raw | ConvertFrom-Json
$prefix=$null
foreach ($property in $settings.PSObject.Properties) {
 if ($property.Name -match '^HexStrike:Targets:(\d+):Id$' -and $property.Value -eq $TargetId) {
  if ($prefix) { throw 'Duplicate target IDs; fix the shared allowlist first.' }
  $prefix='HexStrike:Targets:'+$Matches[1]+':'
 }
}
if (-not $prefix -or $settings.($prefix+'Approved') -ne 'true') { throw 'Target must already be approved in HexStrike:Targets.' }
$hostKey=$prefix+'Hostname'
$existing=$settings.PSObject.Properties[$hostKey]
if ($existing -and $existing.Value -and $existing.Value.TrimEnd('.') -ine $ComputerName.TrimEnd('.')) { throw 'Hostname differs from the existing shared allowlist. Verify target identity before changing it.' }
$bytes=New-Object byte[] 48
$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$token=[Convert]::ToBase64String($bytes)
$sha=[Security.Cryptography.SHA256]::Create()
try { $hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($token)))).Replace('-','') } finally { $sha.Dispose() }
$agentId=[Guid]::NewGuid().ToString('N')
$index=0
while ($settings.PSObject.Properties['Telemetry:Agents:'+$index+':Id']) { $index++ }
$changes=@{'Telemetry:Enabled'='true'}
$changes[$hostKey]=$ComputerName.TrimEnd('.').ToUpperInvariant()
$changes['Telemetry:Agents:'+$index+':Id']=$agentId
$changes['Telemetry:Agents:'+$index+':TargetId']=$TargetId
$changes['Telemetry:Agents:'+$index+':TokenSha256']=$hash
$changes['Telemetry:Agents:'+$index+':Enabled']='true'
$out=Join-Path $repo ('logs\telemetry-enrollment-'+$agentId)
[IO.Directory]::CreateDirectory($out) | Out-Null
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
[IO.Directory]::SetAccessControl($out,$acl)
Copy-Item -LiteralPath (Join-Path $repo 'integrations\windows-agent\Start-WindowsEventAgent.ps1'),(Join-Path $repo 'integrations\windows-agent\Save-AgentToken.ps1') -Destination $out
$utf8=New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $out 'enrollment-token.txt'),$token,$utf8)
$agent=@{Endpoint=$Endpoint.AbsoluteUri;AgentId=$agentId;TokenFile='C:\ProgramData\IncidentPlatformAgent\token.dpapi';StateDirectory='C:\ProgramData\IncidentPlatformAgent\state';Channels=@('Security','System','Application')}
[IO.File]::WriteAllText((Join-Path $out 'agent.json'),($agent|ConvertTo-Json),$utf8)
foreach ($key in $changes.Keys) { $settings | Add-Member -NotePropertyName $key -NotePropertyValue $changes[$key] -Force }
$temp=$secretsPath+'.telemetry.tmp'
[IO.File]::WriteAllText($temp,($settings|ConvertTo-Json -Depth 20),$utf8)
[IO.File]::Replace($temp,$secretsPath,[NullString]::Value)
Write-Host "Enrollment saved: $out"
Write-Host "Agent ID: $agentId; approved target: $TargetId; source IP: $($settings.($prefix+'Ip'))"
Write-Host 'Transfer the token privately. Protect it on the target using Save-AgentToken.ps1, then remove the transfer copies. No service, firewall or VM has been started.'
