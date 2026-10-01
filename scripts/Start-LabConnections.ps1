param([string]$KaliHost='192.168.207.130',[string]$KaliUser='kali')
$ErrorActionPreference='Stop'
$address=$null
if(-not [Net.IPAddress]::TryParse($KaliHost,[ref]$address)){throw 'Supply the verified Kali IP address.'}
$key=Join-Path $env:USERPROFILE '.ssh\incident_lab'
if(-not (Test-Path -LiteralPath $key)){throw 'The incident_lab SSH key is missing.'}
$forwardArgs=@()
foreach($port in @(8888,9443)){
    if(-not (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)){
        $forwardArgs+=@('-L',"127.0.0.1:${port}:127.0.0.1:${port}")
    }
}
if($forwardArgs.Count -eq 0){Write-Output 'Ports 8888 and 9443 already have listeners. Check Lab connections in the app.';exit}
$sshArgs=@('-N','-o','BatchMode=yes','-o','ExitOnForwardFailure=yes','-o','ConnectTimeout=10','-o','ServerAliveInterval=30','-o','ServerAliveCountMax=3','-i',('"'+$key+'"'))+$forwardArgs+@("${KaliUser}@${KaliHost}")
$process=Start-Process ssh -ArgumentList $sshArgs -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2
if($process.HasExited){throw 'SSH tunnel exited. Check Kali SSH and load the incident_lab key in ssh-agent.'}
Write-Output "Lab tunnel started (PID $($process.Id)). HexStrike HTTP 8888 and assessment gateway 9443 are forwarded over SSH."
