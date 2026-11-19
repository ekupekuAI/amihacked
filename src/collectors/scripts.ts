/**
 * Fixed, read-only PowerShell scripts. Nothing here is built from caller input:
 * arguments arrive as JSON in $env:AMIHACKED_ARG. Keep these ASCII-only.
 */

export const PS_AUTORUNS = `
$out = New-Object System.Collections.Generic.List[object]
$keys = @(
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)
foreach ($k in $keys) {
  $item = Get-Item -LiteralPath $k
  if ($item) {
    foreach ($name in $item.GetValueNames()) {
      $out.Add([pscustomobject]@{ location = ($k -replace '^(HK..):\\\\Software\\\\', '$1 '); name = [string]$name; command = [string]$item.GetValue($name, '', 'DoNotExpandEnvironmentNames') })
    }
  }
}
$wl = Get-ItemProperty -LiteralPath 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
foreach ($n in 'Shell', 'Userinit') { $out.Add([pscustomobject]@{ location = 'Winlogon'; name = $n; command = [string]$wl.$n }) }
foreach ($d in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
  if ($d) {
    Get-ChildItem -LiteralPath $d -File | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
      $out.Add([pscustomobject]@{ location = 'Startup folder'; name = [string]$_.Name; command = [string]$_.FullName })
    }
  }
}
ConvertTo-Json -InputObject $out.ToArray() -Depth 3 -Compress
`;

export const PS_TASKS = `
$out = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | ForEach-Object {
  $a = @($_.Actions)[0]
  [pscustomobject]@{
    name = [string]$_.TaskName; taskPath = [string]$_.TaskPath; state = [string]$_.State
    author = [string]$_.Author; runAs = [string]$_.Principal.UserId
    command = ([string]$a.Execute + ' ' + [string]$a.Arguments).Trim()
  }
}
ConvertTo-Json -InputObject @($out) -Depth 3 -Compress
`;

export const PS_SERVICES = `
$out = Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
  [pscustomobject]@{
    name = [string]$_.Name; displayName = [string]$_.DisplayName; command = [string]$_.PathName
    startMode = [string]$_.StartMode; state = [string]$_.State; account = [string]$_.StartName
  }
}
ConvertTo-Json -InputObject @($out) -Depth 3 -Compress
`;

export const PS_PROCESSES = `
$out = Get-CimInstance Win32_Process | ForEach-Object {
  $started = $null
  if ($_.CreationDate) { $started = $_.CreationDate.ToUniversalTime().ToString('o') }
  [pscustomobject]@{
    pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; name = [string]$_.Name
    path = [string]$_.ExecutablePath; commandLine = [string]$_.CommandLine; started = $started
  }
}
ConvertTo-Json -InputObject @($out) -Depth 3 -Compress
`;

export const PS_NETWORK = `
$out = Get-NetTCPConnection -State Listen, Established | ForEach-Object {
  [pscustomobject]@{
    state = [string]$_.State; localAddress = [string]$_.LocalAddress; localPort = [int]$_.LocalPort
    remoteAddress = [string]$_.RemoteAddress; remotePort = [int]$_.RemotePort; pid = [int]$_.OwningProcess
  }
}
ConvertTo-Json -InputObject @($out) -Depth 3 -Compress
`;

export const PS_SIGNATURES = `
$paths = ConvertFrom-Json $env:AMIHACKED_ARG
$out = foreach ($p in @($paths)) {
  $p = [string]$p
  if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
    [pscustomobject]@{ path = $p; status = 'Missing'; signer = '' }
  } else {
    $sig = Get-AuthenticodeSignature -LiteralPath $p
    [pscustomobject]@{ path = $p; status = [string]$sig.Status; signer = [string]$sig.SignerCertificate.Subject }
  }
}
ConvertTo-Json -InputObject @($out) -Depth 3 -Compress
`;

export const PS_DEFENDER = `
$s = Get-MpComputerStatus
$status = $null
if ($s) {
  $status = [pscustomobject]@{
    antivirusEnabled = [bool]$s.AntivirusEnabled; realTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled
    tamperProtected = [bool]$s.IsTamperProtected; runningMode = [string]$s.AMRunningMode
    signatureAgeDays = [int]$s.AntivirusSignatureAge
  }
}
$names = @{}
Get-MpThreat | ForEach-Object { $names[[string]$_.ThreatID] = [string]$_.ThreatName }
$det = Get-MpThreatDetection | Select-Object -First 50 | ForEach-Object {
  $t = $null
  if ($_.InitialDetectionTime) { $t = $_.InitialDetectionTime.ToUniversalTime().ToString('o') }
  [pscustomobject]@{
    threat = [string]$names[[string]$_.ThreatID]; time = $t; path = (@($_.Resources) -join '; ')
    actionSuccess = [bool]$_.ActionSuccess; process = [string]$_.ProcessName
  }
}
$products = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [pscustomobject]@{ name = [string]$_.displayName; state = [int]$_.productState } }
[pscustomobject]@{ status = $status; detections = @($det); products = @($products) } | ConvertTo-Json -Depth 4 -Compress
`;

export const PS_ACCOUNTS = `
$admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [string]$_.Name })
$out = Get-LocalUser | ForEach-Object {
  $name = [string]$_.Name
  $last = $null
  if ($_.LastLogon) { $last = $_.LastLogon.ToUniversalTime().ToString('o') }
  $isAdmin = @($admins | Where-Object { $_.EndsWith('\\' + $name) }).Count -gt 0
  [pscustomobject]@{ name = $name; enabled = [bool]$_.Enabled; lastLogon = $last; isAdmin = $isAdmin }
}
ConvertTo-Json -InputObject @($out) -Depth 3 -Compress
`;

/**
 * Security-relevant events from the live logs (arg.days) or from an .evtx file (arg.path).
 * Only the event IDs the rules understand are read.
 */
export const PS_EVENTS = `
$arg = $env:AMIHACKED_ARG | ConvertFrom-Json
$out = New-Object System.Collections.Generic.List[object]
$gaps = New-Object System.Collections.Generic.List[string]
$specs = @()
if ($arg.path) {
  $max = 6000
  $specs += @{ Path = [string]$arg.path; Id = 4625, 4624, 4720, 4732, 1102, 7045, 104, 4104, 1116, 1117 }
} else {
  $max = 1500
  $since = (Get-Date).AddDays(-[int]$arg.days)
  $specs += @{ LogName = 'Security'; Id = 4625; StartTime = $since }
  $specs += @{ LogName = 'Security'; Id = 4720, 4732, 1102; StartTime = $since }
  $specs += @{ LogName = 'System'; Id = 7045, 104; StartTime = $since }
  $specs += @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3; StartTime = $since }
}
function Add-Events($events) {
  foreach ($e in $events) {
    $f = @{}
    $x = [xml]$e.ToXml()
    foreach ($d in $x.Event.EventData.Data) {
      if ($d.Name) {
        $v = [string]$d.'#text'
        if ($v.Length -gt 2000) { $v = $v.Substring(0, 2000) }
        $f[[string]$d.Name] = $v
      }
    }
    if ($x.Event.UserData -and $x.Event.UserData.FirstChild) {
      foreach ($n in $x.Event.UserData.FirstChild.ChildNodes) { $f[[string]$n.LocalName] = [string]$n.InnerText }
    }
    $out.Add([pscustomobject]@{
      log = [string]$e.LogName; eventId = [int]$e.Id; provider = [string]$e.ProviderName
      time = $e.TimeCreated.ToUniversalTime().ToString('o'); fields = $f
    })
  }
}
foreach ($spec in $specs) {
  try {
    Add-Events (Get-WinEvent -FilterHashtable $spec -MaxEvents $max -ErrorAction Stop)
  } catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
      $label = [string]$spec.LogName
      if (-not $label) { $label = 'file' }
      $gaps.Add($label + ': ' + $_.Exception.Message)
    }
  }
}
if (-not $arg.path) {
  $ms = [int64]$arg.days * 86400000
  $xpath = "*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3']]"
  try {
    Add-Events (Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents $max -ErrorAction Stop)
  } catch { }
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
[pscustomobject]@{ events = $out.ToArray(); gaps = $gaps.ToArray(); admin = [bool]$admin } | ConvertTo-Json -Depth 4 -Compress
`;
