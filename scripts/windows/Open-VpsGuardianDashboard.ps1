# Experimental: validate this launcher in your own Windows and SSH environment.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SshTarget,
    [Parameter(Mandatory)] [string]$IdentityFile,
    [Parameter(Mandatory)] [string]$DashboardDomain,
    [ValidateRange(1, 65535)] [int]$RemotePort = 443,
    [string]$DashboardPath = '/overview',
    [string]$CaCertificate,
    [switch]$RemoveCa
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Find-Executable([string[]]$Candidates) {
    return $Candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
        Select-Object -First 1
}

if ($DashboardDomain -notmatch '^[A-Za-z0-9.-]+$') {
    throw 'DashboardDomain contains invalid characters.'
}
if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
    throw "SSH identity file does not exist: $IdentityFile"
}

if ($CaCertificate) {
    if (-not (Test-Path -LiteralPath $CaCertificate -PathType Leaf)) {
        throw "CA certificate does not exist: $CaCertificate"
    }
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $CaCertificate
    )
    $trusted = Get-ChildItem Cert:\CurrentUser\Root |
        Where-Object Thumbprint -eq $certificate.Thumbprint
    if ($RemoveCa) {
        $trusted | Remove-Item -Force
        Write-Host 'The specified CA was removed from the current user trust store.'
        return
    }
    if (-not $trusted) {
        Import-Certificate -FilePath $CaCertificate -CertStoreLocation Cert:\CurrentUser\Root |
            Out-Null
    }
} elseif ($RemoveCa) {
    throw '-RemoveCa requires -CaCertificate.'
}

$ssh = Find-Executable @((Get-Command ssh.exe -ErrorAction SilentlyContinue).Source)
$edge = Find-Executable @(
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
    (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
)
if (-not $ssh) { throw 'OpenSSH client (ssh.exe) was not found.' }
if (-not $edge) { throw 'Microsoft Edge was not found.' }

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$localPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$profile = Join-Path ([System.IO.Path]::GetTempPath()) (
    'vps-guardian-edge-' + [Guid]::NewGuid().ToString('N')
)
$sshArguments = @(
    '-N', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
    '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30',
    '-o', 'ServerAliveCountMax=3', '-i', $IdentityFile,
    '-L', "127.0.0.1:${localPort}:127.0.0.1:${RemotePort}", $SshTarget
)

$sshProcess = $null
try {
    $sshProcess = Start-Process -FilePath $ssh -ArgumentList $sshArguments `
        -WindowStyle Hidden -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $ready = $false
    do {
        if ($sshProcess.HasExited) {
            throw "SSH tunnel failed (exit code $($sshProcess.ExitCode))."
        }
        Start-Sleep -Milliseconds 200
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $localPort)
            $ready = $client.Connected
        } catch {
            $ready = $false
        } finally {
            $client.Dispose()
        }
    } while (-not $ready -and [DateTime]::UtcNow -lt $deadline)
    if (-not $ready) { throw 'SSH tunnel was not ready within 15 seconds.' }

    New-Item -ItemType Directory -Path $profile | Out-Null
    $path = '/' + $DashboardPath.TrimStart('/')
    $url = "https://${DashboardDomain}:${localPort}${path}"
    # Start-Process joins ArgumentList elements; quote the resolver rule as one argument.
    $resolverRule = '"--host-resolver-rules=MAP {0} 127.0.0.1,EXCLUDE localhost"' -f `
        $DashboardDomain
    $edgeArguments = @(
        "--user-data-dir=$profile", $resolverRule, '--disable-quic',
        '--no-first-run', '--no-default-browser-check', $url
    )
    Start-Process -FilePath $edge -ArgumentList $edgeArguments | Out-Null
    $edgeSeen = $false
    $edgeDeadline = [DateTime]::UtcNow.AddHours(12)
    do {
        Start-Sleep -Milliseconds 500
        $edgeProcesses = Get-CimInstance Win32_Process -Filter "Name = 'msedge.exe'" |
            Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profile) }
        if ($edgeProcesses) { $edgeSeen = $true }
        if ([DateTime]::UtcNow -ge $edgeDeadline) {
            throw 'Timed out waiting for the isolated Edge profile to close.'
        }
    } while ($edgeProcesses -or -not $edgeSeen)
} finally {
    if ($sshProcess -and -not $sshProcess.HasExited) {
        Stop-Process -Id $sshProcess.Id -Force
        $sshProcess.WaitForExit()
    }
    if ($sshProcess) { $sshProcess.Dispose() }
    if (Test-Path -LiteralPath $profile) {
        Remove-Item -LiteralPath $profile -Recurse -Force
    }
}
