#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$TokenFile)
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath $TokenFile) { throw 'Token file already exists. Rotate deliberately; do not overwrite silently.' }
$parent=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($TokenFile))
if ($parent.TrimEnd('\') -eq [IO.Path]::GetPathRoot($parent).TrimEnd('\')) { throw 'Use a dedicated agent folder, not a drive root.' }
[IO.Directory]::CreateDirectory($parent) | Out-Null
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
[IO.Directory]::SetAccessControl($parent,$acl)
$token=Read-Host 'Paste the separately delivered agent token (hidden)' -AsSecureString
$token | ConvertFrom-SecureString | Set-Content -LiteralPath $TokenFile -Encoding ASCII
Write-Host 'Token protected with Windows DPAPI. Run the agent under this same Windows account.'
