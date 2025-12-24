# DevSec Installation Script for Windows v1.0.0
# Usage: iwr -useb https://raw.githubusercontent.com/victoralfred/devsec/main/scripts/install.ps1 | iex
# Or: .\install.ps1 -Version v1.0.0 -InstallDir "C:\custom\path"
#
# Parameters:
#   -Version      Install specific version (default: latest)
#   -InstallDir   Installation directory (default: $env:LOCALAPPDATA\devsec)
#   -Force        Force overwrite existing installation
#   -SkipScanners Skip scanner dependency prompts
#   -AddToPath    Add installation directory to user PATH

[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$InstallDir = "",
    [switch]$Force,
    [switch]$SkipScanners,
    [switch]$AddToPath
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$INSTALL_SCRIPT_VERSION = "1.0.0"
$REPO = "victoralfred/devsec"
$BINARY_NAME = "devsec.exe"
$DEFAULT_INSTALL_DIR = Join-Path $env:LOCALAPPDATA "devsec"

# Utility functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor Blue -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ("-" * $Message.Length) -ForegroundColor Cyan
}

# Detect architecture
function Get-Architecture {
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default {
            Write-Error-Custom "Unsupported architecture: $arch"
            exit 1
        }
    }
}

# Get latest version from GitHub
function Get-LatestVersion {
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest" -Method Get
        return $release.tag_name
    }
    catch {
        Write-Error-Custom "Failed to fetch latest version from GitHub"
        Write-Error-Custom "Please check your internet connection or specify a version with -Version"
        exit 1
    }
}

# Verify checksum
function Test-Checksum {
    param(
        [string]$FilePath,
        [string]$ExpectedHash
    )

    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()

    if ($actualHash -ne $ExpectedHash.ToLower()) {
        Write-Error-Custom "Checksum verification failed!"
        Write-Error-Custom "Expected: $ExpectedHash"
        Write-Error-Custom "Actual:   $actualHash"
        return $false
    }

    return $true
}

# Download and install binary
function Install-Binary {
    param(
        [string]$Version,
        [string]$Arch,
        [string]$InstallPath
    )

    Write-Header "Installing DevSec $Version"

    $archiveName = "devsec_$($Version.TrimStart('v'))_windows_$Arch.zip"
    $downloadUrl = "https://github.com/$REPO/releases/download/$Version/$archiveName"
    $checksumUrl = "https://github.com/$REPO/releases/download/$Version/checksums.txt"

    $tempDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "devsec_install_$(Get-Random)")

    try {
        # Download archive
        Write-Info "Downloading $archiveName..."
        $archivePath = Join-Path $tempDir $archiveName
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing
            Write-Success "Downloaded $archiveName"
        }
        catch {
            Write-Error-Custom "Failed to download $archiveName"
            Write-Error-Custom "URL: $downloadUrl"
            exit 1
        }

        # Download and verify checksum
        Write-Info "Verifying checksum..."
        $checksumPath = Join-Path $tempDir "checksums.txt"
        try {
            Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumPath -UseBasicParsing
            $checksums = Get-Content $checksumPath
            $expectedHash = ($checksums | Where-Object { $_ -match $archiveName } | ForEach-Object { ($_ -split '\s+')[0] })

            if ($expectedHash) {
                if (-not (Test-Checksum -FilePath $archivePath -ExpectedHash $expectedHash)) {
                    exit 1
                }
                Write-Success "Checksum verified"
            }
            else {
                Write-Warn "Checksum not found in checksums.txt, skipping verification"
            }
        }
        catch {
            Write-Warn "Could not download checksums.txt, skipping verification"
        }

        # Extract archive
        Write-Info "Extracting archive..."
        Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force
        Write-Success "Extracted archive"

        # Find binary
        $binaryPath = Join-Path $tempDir $BINARY_NAME
        if (-not (Test-Path $binaryPath)) {
            # Check subdirectory
            $binaryPath = Get-ChildItem -Path $tempDir -Filter $BINARY_NAME -Recurse | Select-Object -First 1 -ExpandProperty FullName
            if (-not $binaryPath) {
                Write-Error-Custom "Binary not found in archive"
                exit 1
            }
        }

        # Create install directory
        Write-Info "Installing to $InstallPath..."
        if (-not (Test-Path $InstallPath)) {
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        }

        # Copy binary
        $destPath = Join-Path $InstallPath $BINARY_NAME
        Copy-Item -Path $binaryPath -Destination $destPath -Force
        Write-Success "Installed $BINARY_NAME to $InstallPath"

        # Verify installation
        try {
            $null = & $destPath version 2>$null
            Write-Success "Installation verified"
        }
        catch {
            Write-Warn "Could not verify installation"
        }
    }
    finally {
        # Cleanup
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Check if scanner is installed
function Test-Scanner {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# Prompt for scanner installation
function Install-Scanners {
    if ($SkipScanners) { return }

    Write-Header "Optional Scanner Dependencies"
    Write-Info "DevSec can integrate with the following security scanners:"
    Write-Host ""

    # Check gitleaks
    if (-not (Test-Scanner "gitleaks")) {
        Write-Host "gitleaks" -ForegroundColor Yellow -NoNewline
        Write-Host " - Secret detection (not installed)"
        Write-Info "  Install with: choco install gitleaks or scoop install gitleaks"
    }
    else {
        Write-Host "gitleaks" -ForegroundColor Green -NoNewline
        Write-Host " - Secret detection (installed)"
    }

    # Check semgrep
    if (-not (Test-Scanner "semgrep")) {
        Write-Host "semgrep" -ForegroundColor Yellow -NoNewline
        Write-Host " - SAST scanning (not installed)"
        Write-Info "  Install with: pip install semgrep"
    }
    else {
        Write-Host "semgrep" -ForegroundColor Green -NoNewline
        Write-Host " - SAST scanning (installed)"
    }

    # Check trivy
    if (-not (Test-Scanner "trivy")) {
        Write-Host "trivy" -ForegroundColor Yellow -NoNewline
        Write-Host " - Vulnerability scanning (not installed)"
        Write-Info "  Install with: choco install trivy or scoop install trivy"
    }
    else {
        Write-Host "trivy" -ForegroundColor Green -NoNewline
        Write-Host " - Vulnerability scanning (installed)"
    }

    Write-Host ""
}

# Check for existing installation
function Test-ExistingInstallation {
    param([string]$InstallPath)

    $binaryPath = Join-Path $InstallPath $BINARY_NAME

    if (Test-Path $binaryPath) {
        if ($Force) {
            Write-Warn "Overwriting existing installation"
            return $true
        }

        try {
            $currentVersion = & $binaryPath version 2>$null
        }
        catch {
            $currentVersion = "unknown"
        }

        Write-Warn "DevSec is already installed at $binaryPath"
        Write-Info "Current version: $currentVersion"

        $response = Read-Host "Overwrite? [y/N]"
        if ($response -notmatch '^[Yy]$') {
            Write-Info "Installation cancelled"
            exit 0
        }
    }

    return $true
}

# Add to PATH
function Add-ToUserPath {
    param([string]$Directory)

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($currentPath -notlike "*$Directory*") {
        $newPath = "$currentPath;$Directory"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Success "Added $Directory to user PATH"
        Write-Info "Restart your terminal for PATH changes to take effect"
    }
}

# Main function
function Main {
    # Enforce TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Print header
    Write-Host ""
    Write-Host "    ____              ____" -ForegroundColor Cyan
    Write-Host "   / __ \___ _   __  / __/___  _____" -ForegroundColor Cyan
    Write-Host "  / / / / _ \ | / / _\ \/ _ \/ ___/" -ForegroundColor Cyan
    Write-Host " / /_/ /  __/ |/ / ___/ /  __/ /__" -ForegroundColor Cyan
    Write-Host "/_____/\___/|___/ /____/\___/\___/" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Installation Script v$INSTALL_SCRIPT_VERSION"
    Write-Host ""

    # Set defaults
    if (-not $InstallDir) {
        $InstallDir = $DEFAULT_INSTALL_DIR
    }

    # Detect platform
    Write-Header "Detecting Platform"
    $arch = Get-Architecture
    Write-Success "Platform: windows/$arch"

    # Get version
    Write-Header "Resolving Version"
    if (-not $Version) {
        Write-Info "Fetching latest version..."
        $Version = Get-LatestVersion
    }
    Write-Success "Version: $Version"

    # Check existing installation
    Test-ExistingInstallation -InstallPath $InstallDir | Out-Null

    # Install binary
    Install-Binary -Version $Version -Arch $arch -InstallPath $InstallDir

    # Prompt for scanner installation
    Install-Scanners

    # Add to PATH if requested
    if ($AddToPath) {
        Add-ToUserPath -Directory $InstallDir
    }

    # Final message
    Write-Header "Installation Complete"
    Write-Success "DevSec $Version has been installed to $InstallDir\$BINARY_NAME"
    Write-Host ""
    Write-Info "Get started:"
    Write-Host "  $InstallDir\$BINARY_NAME --help"
    Write-Host "  $InstallDir\$BINARY_NAME scan secrets ."
    Write-Host "  $InstallDir\$BINARY_NAME scan sast ."
    Write-Host ""

    # Check if install dir is in PATH
    $envPath = [Environment]::GetEnvironmentVariable("Path", "User") + ";" + [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($envPath -notlike "*$InstallDir*") {
        Write-Warn "$InstallDir is not in your PATH"
        Write-Info "Add it with: [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$InstallDir', 'User')"
        Write-Info "Or run this script with -AddToPath"
        Write-Host ""
    }
}

Main
