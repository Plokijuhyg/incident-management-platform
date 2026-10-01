#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ConfigPath, [switch]$Once)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$endpoint = [Uri]$config.Endpoint
if ($endpoint.Scheme -ne 'https' -or $endpoint.AbsolutePath -ne '/api/telemetry/events' -or $endpoint.UserInfo -or $endpoint.Query -or $endpoint.Fragment) { throw 'An exact HTTPS telemetry endpoint is required.' }
if (-not [IO.Path]::IsPathRooted($config.StateDirectory) -or -not [IO.Path]::IsPathRooted($config.TokenFile)) { throw 'StateDirectory and TokenFile must be absolute paths.' }
# TokenFile is DPAPI-protected for the current Windows account, created with Save-AgentToken.ps1.
$secure = (Get-Content -LiteralPath $config.TokenFile -Raw).Trim() | ConvertTo-SecureString
$token = (New-Object System.Net.NetworkCredential('', $secure)).Password
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$utf8 = New-Object System.Text.UTF8Encoding($false)
$resolvedState=[IO.Path]::GetFullPath($config.StateDirectory)
if ($resolvedState.TrimEnd('\') -eq [IO.Path]::GetPathRoot($resolvedState).TrimEnd('\')) { throw 'Use a dedicated state folder, not a drive root.' }
$stateDir = [IO.Directory]::CreateDirectory($resolvedState).FullName
# Raw events and cursors are private to the service account and SYSTEM.
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
[IO.Directory]::SetAccessControl($stateDir,$acl)
$lock = [IO.File]::Open((Join-Path $stateDir 'agent.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
function Save-State($path, $value) {
    $temp = $path + '.tmp'
    [IO.File]::WriteAllText($temp, ($value | ConvertTo-Json -Depth 12 -Compress), $utf8)
    if ([IO.File]::Exists($path)) { [IO.File]::Replace($temp, $path, [NullString]::Value) }
    else { [IO.File]::Move($temp, $path) }
}
function Send-Batch($batch) {
    $bytes = $utf8.GetBytes(($batch | ConvertTo-Json -Depth 10 -Compress))
    $request = [Net.HttpWebRequest]::Create($endpoint)
    $request.Method='POST'; $request.ContentType='application/json'; $request.ContentLength=$bytes.Length
    $request.AllowAutoRedirect=$false; $request.Timeout=30000; $request.ReadWriteTimeout=30000; $request.Proxy=$null
    $request.Headers.Add('X-Agent-Id',[string]$config.AgentId)
    $request.Headers.Add('X-Telemetry-Token',$token)
    # Normal OS certificate chain/hostname validation remains enabled. Never bypass TLS validation.
    $stream=$request.GetRequestStream()
    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    $response=$request.GetResponse()
    try {
        if ([int]$response.StatusCode -ne 200) { throw 'No successful acknowledgement' }
        $reader=New-Object IO.StreamReader($response.GetResponseStream())
        try { $ack=$reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        if ($ack.batchId -ne $batch.batchId -or ([int]$ack.accepted+[int]$ack.duplicates) -ne @($batch.events).Count) { throw 'Invalid acknowledgement; batch retained' }
    } finally { $response.Dispose() }
}
try {
    do {
        $channels=@($config.Channels)
        if ($channels -contains '*') {
            $session=New-Object System.Diagnostics.Eventing.Reader.EventLogSession
            try { $channels=@($session.GetLogNames()) } finally { $session.Dispose() }
        }
        foreach ($channel in $channels) {
            try {
                $sha=[Security.Cryptography.SHA256]::Create()
                try { $key=([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($channel)))).Replace('-','') } finally { $sha.Dispose() }
                $path=Join-Path $stateDir ($key+'.json')
                if (Test-Path -LiteralPath $path) { $state=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
                else { $state=[pscustomobject]@{channel=$channel;cursor=$null;start=[DateTime]::UtcNow.AddMinutes(-5).ToString('o');pending=$null;pendingCursor=$null} }
                # Durable pending batch is retried before reading any more records from this channel.
                if ($null -eq $state.pending) {
                    $settings=New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($channel)
                    try { if (-not $settings.IsEnabled) { continue } } finally { $settings.Dispose() }
                    $xpath="*[System[TimeCreated[@SystemTime >= '$($state.start)']]]"
                    if ($state.cursor) {
                        $recordId=[long]$state.cursor.recordId
                        # Detect clearing/rollover instead of silently skipping or resetting a source.
                        $anchor=Get-WinEvent -LogName $channel -FilterXPath "*[System[EventRecordID=$recordId]]" -MaxEvents 1 -ErrorAction Stop
                        try {
                            if ($anchor.TimeCreated.ToUniversalTime().ToString('o') -ne $state.cursor.time) { throw 'Cursor identity changed; review cleared log before resetting this channel.' }
                        } finally { $anchor.Dispose() }
                        $xpath="*[System[EventRecordID > $recordId]]"
                    }
                    $query=New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($channel,[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
                    $reader=New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
                    $events=New-Object System.Collections.Generic.List[object]
                    $batchId=[Guid]::NewGuid().ToString()
                    try {
                        for ($i=0; $i -lt 16; $i++) {
                            $record=$reader.ReadEvent([TimeSpan]::FromSeconds(1))
                            if ($null -eq $record) { break }
                            try {
                                $xml=$record.ToXml()
                                if ($xml.Length -gt 65536) { throw 'Oversized event: channel paused without advancing cursor; operator review required.' }
                                try { $message=$record.FormatDescription() } catch { $message='Message resource unavailable; inspect XML.' }
                                if ($message -and $message.Length -gt 8192) { $message=$message.Substring(0,8192) }
                                $events.Add(@{rawXml=$xml;message=$message})
                                $candidate=@{batchId=$batchId;events=@($events.ToArray())}
                                if ($utf8.GetByteCount(($candidate | ConvertTo-Json -Depth 10 -Compress)) -gt 1500000) { $events.RemoveAt($events.Count-1); break }
                                $state.pendingCursor=[pscustomobject]@{recordId=$record.RecordId;time=$record.TimeCreated.ToUniversalTime().ToString('o')}
                            } finally { $record.Dispose() }
                        }
                    } finally { $reader.Dispose() }
                    if ($events.Count -eq 0) { continue }
                    $size=(Get-ChildItem -LiteralPath $stateDir -File | Measure-Object -Property Length -Sum).Sum
                    if ($size -gt 268435456) { throw 'Agent spool limit reached; collection paused without advancing cursors.' }
                    $state.pending=@{batchId=$batchId;events=@($events.ToArray())}
                    Save-State $path $state
                }
                Send-Batch $state.pending
                $state.cursor=$state.pendingCursor; $state.pending=$null; $state.pendingCursor=$null
                Save-State $path $state
                Write-Host ([DateTime]::UtcNow.ToString('o')+' acknowledged '+$channel)
            } catch {
                # No tokens or event bodies in operational output. Leave the durable cursor/pending batch unchanged.
                Write-Warning ($channel+': '+$_.Exception.Message)
            }
        }
        if (-not $Once) { Start-Sleep -Seconds 5 }
    } while (-not $Once)
} finally { $lock.Dispose(); $token=$null }
