<#
Enumerate mDNS (224.0.0.251:5353) service types and instances with safe parsing.
Usage:
  .\Find-mDNS.ps1
  .\Find-mDNS.ps1 -QueryInstances -ListenSeconds 8 -OutCsv .\mdns.csv -OutJson .\mdns.json
#>

[CmdletBinding()]
param(
  [int]$ListenSeconds = 6,
  [switch]$QueryInstances,
  [string]$OutCsv,
  [string]$OutJson
)

# ----------------------- Primitives ----------------------- #

function Read-UInt16BE { param([byte[]]$b,[ref]$o)
  if ($o.Value + 2 -gt $b.Length) { throw "Truncated UInt16" }
  $v = ($b[$o.Value] -shl 8) -bor $b[$o.Value+1]; $o.Value += 2; return [uint16]$v
}
function Read-UInt32BE { param([byte[]]$b,[ref]$o)
  if ($o.Value + 4 -gt $b.Length) { throw "Truncated UInt32" }
  $v = ($b[$o.Value] -shl 24) -bor ($b[$o.Value+1] -shl 16) -bor ($b[$o.Value+2] -shl 8) -bor $b[$o.Value+3]
  $o.Value += 4; return [uint32]$v
}

function Encode-DnsName {
  param([string]$Name)
  $ms = New-Object System.IO.MemoryStream
  $bw = New-Object System.IO.BinaryWriter($ms,[Text.Encoding]::ASCII)
  foreach ($label in $Name.TrimEnd('.').Split('.')) {
    $bytes = [Text.Encoding]::ASCII.GetBytes($label)
    $bw.Write([byte]$bytes.Length)
    $bw.Write($bytes)
  }
  $bw.Write([byte]0) # terminator
  $bw.Flush()
  ,$ms.ToArray()
}

# SAFE decoder with bounds/pointer checks (prevents "Index and count..." errors)
function Decode-DnsName {
  param([byte[]]$Bytes, [ref]$Offset)
  $labels = New-Object System.Collections.Generic.List[string]
  $jumped = $false
  $seen   = New-Object System.Collections.Generic.HashSet[int]
  $cursor = $Offset.Value
  $maxLen = $Bytes.Length

  for ($i=0; $i -lt 256; $i++) {
    if ($cursor -ge $maxLen) { break }
    $len = $Bytes[$cursor]

    if ($len -eq 0) {
      $cursor++
      if (-not $jumped) { $Offset.Value = $cursor }
      return ($labels -join '.')
    }

    if ( ($len -band 0xC0) -eq 0xC0 ) {
      if ($cursor + 1 -ge $maxLen) { break }
      $b2  = $Bytes[$cursor + 1]
      $ptr = (($len -band 0x3F) -shl 8) -bor $b2
      if ($ptr -lt 0 -or $ptr -ge $maxLen) { break }
      if ($seen.Contains($ptr)) { break }
      [void]$seen.Add($ptr)

      if (-not $jumped) { $Offset.Value = $cursor + 2; $jumped = $true }
      $cursor = $ptr
      continue
    }

    $cursor++
    if ($cursor + $len -gt $maxLen) { break }
    $label = [Text.Encoding]::ASCII.GetString($Bytes, $cursor, $len)
    $labels.Add($label)
    $cursor += $len
  }

  if (-not $jumped) { $Offset.Value = [Math]::Min($cursor, $maxLen) }
  return ($labels -join '.')
}

function New-DnsQueryPacket {
  param([string]$QName,[UInt16]$QType)

  $ms = New-Object System.IO.MemoryStream
  $bw = New-Object System.IO.BinaryWriter($ms,[Text.Encoding]::ASCII)

  # Header: ID=0, flags=0x0000, QD=1, AN=0, NS=0, AR=0
  $bw.Write([byte]0); $bw.Write([byte]0)   # ID
  $bw.Write([byte]0); $bw.Write([byte]0)   # FLAGS
  $bw.Write([byte]0); $bw.Write([byte]1)   # QDCOUNT
  $bw.Write([byte]0); $bw.Write([byte]0)   # ANCOUNT
  $bw.Write([byte]0); $bw.Write([byte]0)   # NSCOUNT
  $bw.Write([byte]0); $bw.Write([byte]0)   # ARCOUNT

  # QNAME
  $qnameBytes = Encode-DnsName $QName
  $bw.Write($qnameBytes)

  # QTYPE (big-endian)
  $bw.Write([byte]($QType -shr 8))
  $bw.Write([byte]($QType -band 0xFF))

  # QCLASS IN (0x0001)
  $bw.Write([byte]0); $bw.Write([byte]1)

  $bw.Flush()
  ,$ms.ToArray()
}

function New-UdpMulticast5353 {
  $udp = New-Object System.Net.Sockets.UdpClient
  $udp.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket,
                              [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
  $udp.ExclusiveAddressUse = $false
  $udp.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 5353))
  try { $udp.JoinMulticastGroup([System.Net.IPAddress]::Parse("224.0.0.251")) } catch {}
  return $udp
}

function Send-mDNSQuery {
  param([System.Net.Sockets.UdpClient]$Udp, [byte[]]$Packet)
  $mcastEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse("224.0.0.251"), 5353)
  [void]$Udp.Send($Packet, $Packet.Length, $mcastEP)
}

function Receive-mDNS {
  param([System.Net.Sockets.UdpClient]$Udp, [int]$Seconds)

  $records = @()
  $deadline = (Get-Date).AddSeconds($Seconds)

  while ((Get-Date) -lt $deadline) {
    if ($Udp.Available -le 0) { Start-Sleep -Milliseconds 50; continue }
    $remoteRef = [Ref]([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0))
    $bytes = $Udp.Receive([ref]$remoteRef.Value)
    if (-not $bytes) { continue }

    $o = [ref]0
    try {
      # Header
      $id     = Read-UInt16BE $bytes $o
      $flags  = Read-UInt16BE $bytes $o
      $qd     = Read-UInt16BE $bytes $o
      $an     = Read-UInt16BE $bytes $o
      $ns     = Read-UInt16BE $bytes $o
      $ar     = Read-UInt16BE $bytes $o

      # Skip questions
      for ($i=0; $i -lt $qd; $i++) {
        [void](Decode-DnsName $bytes $o)
        [void](Read-UInt16BE $bytes $o) # qtype
        [void](Read-UInt16BE $bytes $o) # qclass
      }

      $totalRR = $an + $ns + $ar
      for ($r=0; $r -lt $totalRR; $r++) {
        $name  = Decode-DnsName $bytes $o
        $type  = Read-UInt16BE $bytes $o
        $class = Read-UInt16BE $bytes $o
        $ttl   = Read-UInt32BE $bytes $o
        $rdl   = Read-UInt16BE $bytes $o

        # Guard: RDLEN must fit in buffer
        if ($o.Value + $rdl -gt $bytes.Length) {
          $o.Value = $bytes.Length
          continue
        }

        switch ($type) {
          1 { # A
            if ($rdl -eq 4) {
              $ip = [System.Net.IPAddress]::new($bytes[$o.Value..($o.Value+3)])
              $records += [pscustomobject]@{ Name=$name; Type='A'; TTL=$ttl; IP=$ip.IPAddressToString; Target=$null; Port=$null; TXT=$null }
            }
            $o.Value += $rdl
          }
          28 { # AAAA
            if ($rdl -eq 16) {
              $addr = New-Object byte[] 16
              [Array]::Copy($bytes, $o.Value, $addr, 0, 16)
              $ip6 = [System.Net.IPAddress]::new($addr)
              $records += [pscustomobject]@{ Name=$name; Type='AAAA'; TTL=$ttl; IP=$ip6.IPAddressToString; Target=$null; Port=$null; TXT=$null }
            }
            $o.Value += $rdl
          }
          12 { # PTR
            $ptrName = Decode-DnsName $bytes $o
            $records += [pscustomobject]@{ Name=$name; Type='PTR'; TTL=$ttl; IP=$null; Target=$ptrName; Port=$null; TXT=$null }
          }
          33 { # SRV
            $prio   = Read-UInt16BE $bytes $o
            $weight = Read-UInt16BE $bytes $o
            $port   = Read-UInt16BE $bytes $o
            $target = Decode-DnsName $bytes $o
            $records += [pscustomobject]@{ Name=$name; Type='SRV'; TTL=$ttl; IP=$null; Target=$target; Port=$port; TXT=$null }
          }
          16 { # TXT
            $txts = New-Object System.Collections.Generic.List[string]
            $end = $o.Value + $rdl
            while ($o.Value -lt $end) {
              $len = $bytes[$o.Value]; $o.Value++
              if ($len -le 0) { continue }
              $avail = [Math]::Min($len, ($end - $o.Value))
              $txts.Add([Text.Encoding]::ASCII.GetString($bytes, $o.Value, $avail))
              $o.Value += $len
            }
            $records += [pscustomobject]@{ Name=$name; Type='TXT'; TTL=$ttl; IP=$null; Target=$null; Port=$null; TXT=($txts -join ';') }
          }
          default {
            $o.Value += $rdl
          }
        }
      }
    } catch {
      continue
    }
  }

  return @($records)
}

# ----------------------- Workflow ----------------------- #

$udp = New-UdpMulticast5353

# 1) Service TYPES via PTR on _services._dns-sd._udp.local
$enumPacket = New-DnsQueryPacket -QName "_services._dns-sd._udp.local" -QType 12  # PTR
Send-mDNSQuery -Udp $udp -Packet $enumPacket
$records = Receive-mDNS -Udp $udp -Seconds $ListenSeconds

$serviceTypes = $records |
  Where-Object { $_.Type -eq 'PTR' -and $_.Name -ieq "_services._dns-sd._udp.local" } |
  Select-Object -ExpandProperty Target -Unique |
  Sort-Object

# 2) Optionally query each service TYPE for instances (PTR)
$more = @()
if ($QueryInstances -and $serviceTypes) {
  foreach ($stype in $serviceTypes) {
    $pkt = New-DnsQueryPacket -QName $stype -QType 12
    Send-mDNSQuery -Udp $udp -Packet $pkt
  }
  $more = Receive-mDNS -Udp $udp -Seconds $ListenSeconds
}

$all = @()
if ($records) { $all += @($records) }
if ($more)    { $all += @($more) }

# Build instance list from PTR (excluding the service-type enumeration name)
$instances = $all | Where-Object { $_.Type -eq 'PTR' -and $_.Name -ne "_services._dns-sd._udp.local" } |
  Group-Object Name | ForEach-Object {
    $serviceType = $_.Name
    foreach ($rec in $_.Group) {
      [pscustomobject]@{ ServiceType = $serviceType; Instance = $rec.Target }
    }
  }

# Indexes
$srvs  = $all | Where-Object { $_.Type -eq 'SRV'  }
$as    = $all | Where-Object { $_.Type -eq 'A'    }
$aaaas = $all | Where-Object { $_.Type -eq 'AAAA' }
$txts  = $all | Where-Object { $_.Type -eq 'TXT'  }

# Join SRV -> host/port, then host -> IPs, gather TXT
$report = foreach ($inst in $instances) {
  $srv = $srvs | Where-Object { $_.Name -eq $inst.Instance } | Select-Object -First 1
  $TargetHost = if ($srv) { $srv.Target } else { $null }
  $port = if ($srv) { $srv.Port } else { $null }

  $ipv4 = if ($TargetHost) {
    ($as | Where-Object { $_.Name -eq $TargetHost } | Select-Object -ExpandProperty IP -Unique) -join ', '
  }
  $ipv6 = if ($TargetHost) {
    ($aaaas | Where-Object { $_.Name -eq $TargetHost } | Select-Object -ExpandProperty IP -Unique) -join ', '
  }

  $txt = ($txts | Where-Object { $_.Name -eq $inst.Instance } | Select-Object -ExpandProperty TXT -Unique) -join ' | '

  [pscustomobject]@{
    ServiceType = $inst.ServiceType
    Instance    = $inst.Instance
    Hostname    = $TargetHost
    IPv4        = $ipv4
    IPv6        = $ipv6
    Port        = $port
    TXT         = $txt
  }
}


# Output
Write-Host "`n== Discovered Service Types ==" -ForegroundColor Cyan
if ($serviceTypes) { $serviceTypes | ForEach-Object { $_ } } else { Write-Host "(none)" -ForegroundColor DarkGray }

Write-Host "`n== Service Instances ==" -ForegroundColor Cyan
if ($report -and $report.Count -gt 0) {
  $report | Sort-Object ServiceType, Instance | Format-Table -AutoSize
} else {
  if ($QueryInstances) {
    Write-Host "No instances resolved (try longer -ListenSeconds, or devices may not be advertising)." -ForegroundColor Yellow
  } else {
    Write-Host "Instance enumeration not run. Re-run with -QueryInstances to enumerate instances." -ForegroundColor Yellow
  }
}

# ----------------------- Optional exports ----------------------- #

function Resolve-ExportPath {
    param([string]$Path)

    if (-not $Path) { return $null }

    # If just a filename (no slashes) → Desktop
    if (-not ($Path -match '[\\/]' )) {
        $desktop = [Environment]::GetFolderPath('Desktop')
        return (Join-Path $desktop $Path)
    }

    # If relative (starts with .\ or ..\) → resolve relative to current location ($PWD)
    if ($Path.StartsWith('.\') -or $Path.StartsWith('..\')) {
        return (Join-Path $PWD $Path)
    }

    # Otherwise assume it's already an absolute path
    return [System.IO.Path]::GetFullPath($Path)
}


$csvPath  = Resolve-ExportPath -Path $OutCsv
$jsonPath = Resolve-ExportPath -Path $OutJson

if ($csvPath) {
    try {
        # Ensure target directory exists
        $csvDir = [System.IO.Path]::GetDirectoryName($csvPath)
        if ($csvDir -and -not (Test-Path -LiteralPath $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

        $report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Saved CSV: $csvPath" -ForegroundColor Green
    } catch { Write-Host "CSV export failed: $_" -ForegroundColor Red }
}

if ($jsonPath) {
    try {
        $jsonDir = [System.IO.Path]::GetDirectoryName($jsonPath)
        if ($jsonDir -and -not (Test-Path -LiteralPath $jsonDir)) { New-Item -ItemType Directory -Path $jsonDir -Force | Out-Null }

        $report | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
        Write-Host "Saved JSON: $jsonPath" -ForegroundColor Green
    } catch { Write-Host "JSON export failed: $_" -ForegroundColor Red }
}


# Cleanup
try { $udp.DropMulticastGroup([System.Net.IPAddress]::Parse("224.0.0.251")) } catch {}
$udp.Close()
