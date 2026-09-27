#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$ForceReinstall,
    [switch]$UseExeInstaller,
    [switch]$RequireNetwork
)

$ErrorActionPreference = "Stop"

$ServerHost = "192.168.10.10"
$ServerPort = 8000
$ServiceName = "Velociraptor"
$MsiName = "Velociraptor-Windows-Client-192.168.10.10.msi"
$ExeName = "Velociraptor-Windows-Client-192.168.10.10.exe"
$ConfigName = "client.config.yaml"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MsiPath = Join-Path $ScriptDir $MsiName
$ExePath = Join-Path $ScriptDir $ExeName
$ConfigPath = Join-Path $ScriptDir $ConfigName

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator, then run this script again."
    }
}

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port
    )

    try {
        $client = New-Object Net.Sockets.TcpClient
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(3000, $false)) {
            $client.Close()
            return $false
        }

        $client.EndConnect($async)
        $client.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-CheckedProcess {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [int[]]$AllowedExitCodes = @(0)
    )

    Write-Step ("Running: {0} {1}" -f $FilePath, ($ArgumentList -join " "))
    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -Wait -PassThru
    if ($AllowedExitCodes -notcontains $process.ExitCode) {
        throw "Command failed with exit code $($process.ExitCode): $FilePath"
    }
}

function Get-VelociraptorService {
    Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

Assert-Administrator

Write-Step "Checking TCP connectivity to ${ServerHost}:$ServerPort"
$networkOk = Test-TcpPort -HostName $ServerHost -Port $ServerPort
if ($networkOk) {
    Write-Step "Server is reachable."
}
else {
    $message = "Cannot reach ${ServerHost}:$ServerPort from this Windows host."
    if ($RequireNetwork) {
        throw $message
    }
    Write-Warning "$message Install will continue, but the client will not show online until network routing/firewall is fixed."
}

$existingService = Get-VelociraptorService
if ($existingService -and -not $ForceReinstall) {
    Write-Step "Service '$ServiceName' already exists. Current status: $($existingService.Status)"
    if ($existingService.Status -ne "Running") {
        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 3
    }
    Get-Service -Name $ServiceName
    Write-Step "Use -ForceReinstall if you intentionally want to reinstall."
    exit 0
}

if ($existingService -and $ForceReinstall) {
    Write-Step "Force reinstall requested."
    if ((Test-Path $MsiPath) -and -not $UseExeInstaller) {
        Write-Step "Uninstalling existing MSI package if present"
        Invoke-CheckedProcess -FilePath "msiexec.exe" -ArgumentList @("/x", "`"$MsiPath`"", "/qn", "/norestart") -AllowedExitCodes @(0, 1605, 3010)
        Start-Sleep -Seconds 5
    }

    $existingService = Get-VelociraptorService
}

if ($existingService -and $ForceReinstall) {
    Write-Step "Stopping and removing existing service '$ServiceName' as fallback"
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning $_.Exception.Message
    }

    if (Test-Path $ExePath) {
        Invoke-CheckedProcess -FilePath $ExePath -ArgumentList @("service", "remove")
    }
    else {
        sc.exe delete $ServiceName | Out-Host
    }
    Start-Sleep -Seconds 3
}

if ((Test-Path $MsiPath) -and -not $UseExeInstaller) {
    Write-Step "Installing Velociraptor client using repacked MSI"
    Invoke-CheckedProcess -FilePath "msiexec.exe" -ArgumentList @("/i", "`"$MsiPath`"", "/qn", "/norestart") -AllowedExitCodes @(0, 3010)
}
elseif (Test-Path $ExePath) {
    Write-Step "Installing Velociraptor client using EXE service installer"
    if (Test-Path $ConfigPath) {
        Invoke-CheckedProcess -FilePath $ExePath -ArgumentList @("service", "install", "--config", "`"$ConfigPath`"", "-v")
    }
    else {
        Invoke-CheckedProcess -FilePath $ExePath -ArgumentList @("service", "install", "-v")
    }
}
else {
    throw "No installer found. Expected '$MsiPath' or '$ExePath'."
}

Start-Sleep -Seconds 5
$service = Get-VelociraptorService
if (-not $service) {
    throw "Install finished but service '$ServiceName' was not found."
}

if ($service.Status -ne "Running") {
    Write-Step "Starting service '$ServiceName'"
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
}

Write-Step "Velociraptor client service status:"
Get-Service -Name $ServiceName

Write-Step "Useful checks:"
Write-Host "  sc.exe query $ServiceName"
Write-Host "  Test-NetConnection $ServerHost -Port $ServerPort"
Write-Host "  Get-Content 'C:\Program Files\Velociraptor\velociraptor.writeback.yaml' -ErrorAction SilentlyContinue"
