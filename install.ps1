#!/usr/bin/env pwsh
<#
.SYNOPSIS
    CLI installation script for nn-cli
.DESCRIPTION
    Downloads and installs the latest release of nn-cli from Github
    Supports both ZIP archives and direct executable downloads
.PARAMETER InstallPath
    Directory to install nn-cli to. Defaults to $HOME\.nn-cli
.PARAMETER Force
    Force reinstallation even if nn-cli is already installed
.PARAMETER Help
    Show help message
.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -InstallPath "C:\tools\nn-cli" -Force
.EXAMPLE
    iex (irm 'https://raw.githubusercontent.com/NovoNordisk-OpenSource/nn-cli-installers/refs/heads/main/install.ps1')
#>

param(
    [string]$InstallPath = $(if ($IsWindows -or $env:OS -like "*Windows*") { "$HOME\.nn\bin" } else { "$HOME/.nn/bin" }),
    [switch]$Force,
    [switch]$Help,
    [switch]$Debug,
    [switch]$DryRun,
    [switch]$TestAuth,
    [switch]$Quiet,
    
    # Pre-release support
    [string]$PreRelease = "",
    
    # Failure injection testing parameters
    [switch]$InjectBadDownload,
    [switch]$InjectNetworkFail,
    [switch]$InjectAuthFail,
    [switch]$InjectPreReleaseNotFound,
    [switch]$InjectNoPreReleases,
    [int]$MaxRetries = 3
)

# Set strict error handling
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Constants
$RepoOwner = "nn-gdai"
$RepoName = "nn-cli"
$BinaryPattern = "nn-cli-*-windows-amd64.zip"
$LegacyBinaryName = "nn-windows-amd64.exe"
$ExeName = "nn.exe"

function Write-Info {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Information "[INFO] $Message" -InformationAction Continue
    }
}

function Write-Success {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Information "[OK] $Message" -InformationAction Continue
    }
}

function Write-Debug-Info {
    param([string]$Message)
    if ($Debug) {
        Write-Information "[DEBUG] $Message" -InformationAction Continue
    }
}

function Write-Warning-Info {
    param([string]$Message)
    Write-Warning "[WARN] $Message"
}

function Test-Authentication {
    Write-Info "Testing GitHub authentication..."
    
    try {
        Write-Debug-Info "Username: $env:GITHUB_USERNAME"
        Write-Debug-Info "Token present: $([bool]$env:GITHUB_TOKEN)"
        
        $headers = Get-AuthHeaders
        $apiUrl = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
        
        Write-Debug-Info "API URL: $apiUrl"
        Write-Debug-Info "Testing authentication headers..."
        
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -UseBasicParsing
        
        Write-Success "Authentication test passed!"
        Write-Info "Latest release: $($response.tag_name)"
        
        if ($Debug) {
            Write-Debug-Info "Total assets: $($response.assets.Count)"
            Write-Debug-Info "Published: $($response.published_at)"
        }
        
        return $true
    }
    catch {
        Write-Error "Authentication test failed: $($_.Exception.Message)"
        if ($Debug) {
            Write-Debug-Info "Full error details: $($_ | Out-String)"
        }
        return $false
    }
}

function Get-AuthHeaders {
    $username = $env:GITHUB_USERNAME
    $token = $env:GITHUB_TOKEN
    
    Write-Debug-Info "Getting auth headers for user: $(if ($username) { $username } else { '<not set>' })"
    
    # Inject authentication failure for testing
    if ($InjectAuthFail) {
        Write-Debug-Info "Injecting authentication failure for testing"
        $username = "fake-user"
        $token = "fake-token" 
        Write-Warning-Info "TESTING: Using fake credentials to simulate auth failure"
    }
    
    # Note: Authentication check is now done in Get-LatestRelease
    # This function assumes credentials are available
    
    Write-Info "Using Github authentication for $username"
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${token}"))
    Write-Debug-Info "Auth string created (length: $($auth.Length))"
    
    return @{
        "Authorization"        = "Basic $auth"
        "Accept"               = "application/vnd.github+json"
        "X-Github-Api-Version" = "2022-11-28"
        "User-Agent"           = "nn-cli-installer/1.0"
    }
}

function Get-LatestRelease {
    try {
        Write-Info "Fetching latest release information..."
        $apiUrl = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
        
        # Check authentication first
        $username = $env:GITHUB_USERNAME
        $token = $env:GITHUB_TOKEN
        
        if (-not $username -or -not $token) {
            Write-Error "GitHub authentication required to access nn-cli releases"
            Write-Info ""
            Write-Info "Please set these environment variables before running the installer:"
            Write-Info "  `$env:GITHUB_USERNAME = 'your-github-username'"
            Write-Info "  `$env:GITHUB_TOKEN = 'your-personal-access-token'"
            Write-Info ""
            Write-Info "Example:"
            Write-Info "  `$env:GITHUB_USERNAME = 'john.doe'"
            Write-Info "  `$env:GITHUB_TOKEN = 'ghp_xxxxxxxxxxxxx'"
            Write-Info ""
            Write-Info "Then run the installer again."
            exit 1
        }
        
        $headers = Get-AuthHeaders
        
        try {
            $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -UseBasicParsing -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq 404) {
                Write-Error "Repository or releases not found."
                Write-Info "This could mean:"
                Write-Info "1. No releases have been published yet"
                Write-Info "2. You don't have access to the repository"
                Write-Info "3. The repository doesn't exist"
                throw "No accessible releases found"
            }
            else {
                throw "Network error: $($_.Exception.Message)"
            }
        }
        
        if ($response.assets.Count -eq 0) {
            throw "No assets found in the latest release"
        }
        
        # Try to find Windows ZIP archive first (preferred)
        $windowsAsset = $response.assets | Where-Object { $_.name -match "nn-cli-.*-windows-amd64\.zip$" }
        
        if (-not $windowsAsset) {
            # Try legacy naming pattern (direct exe)
            $windowsAsset = $response.assets | Where-Object { $_.name -match "nn-windows-amd64.*\.exe$" }
        }
        
        if (-not $windowsAsset) {
            # Try exact legacy name
            $windowsAsset = $response.assets | Where-Object { $_.name -eq $LegacyBinaryName }
        }
        
        if (-not $windowsAsset) {
            Write-Warning "Windows binary not found in release assets"
            Write-Info "Expected: nn-cli-*-windows-amd64.zip or nn-windows-amd64.exe"
            Write-Info "Available assets:"
            $response.assets | ForEach-Object { Write-Info "  - $($_.name)" }
            throw "Windows binary not found in release assets"
        }
        
        Write-Info "Found Windows asset: $($windowsAsset.name)"
        
        return @{
            Version     = $response.tag_name
            DownloadUrl = $windowsAsset.browser_download_url
            AssetId     = $windowsAsset.id
            Size        = $windowsAsset.size
            AssetName   = $windowsAsset.name
        }
    }
    catch {
        Write-Error "Failed to get latest release information: $($_.Exception.Message)"
        Write-Info ""
        Write-Info "Alternative installation methods:"
        Write-Info "1. Manual download from: https://github.com/$RepoOwner/$RepoName/releases"
        Write-Info "2. Build from source:"
        Write-Info "   git clone https://github.com/$RepoOwner/$RepoName.git"
        Write-Info "   cd $RepoName/src"
        Write-Info "   make build-windows-amd64"
        Write-Info "   copy ../out/nn-cli/bin/nn-cli-*-windows-amd64.exe `$InstallPath\nn.exe"
        exit 1
    }
}

function Test-ExistingInstallation {
    $exePath = Join-Path -Path $InstallPath -ChildPath $ExeName
    if (Test-Path $exePath) {
        try {
            $currentVersion = & $exePath version 2>$null | Select-String "Version:\s*(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
            return $currentVersion
        }
        catch {
            return "unknown"
        }
    }
    return $null
}

function New-InstallDirectory {
    if (-not (Test-Path $InstallPath)) {
        Write-Info "Creating installation directory: $InstallPath"
        try {
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        }
        catch {
            Write-Error "Failed to create installation directory: $_"
            exit 1
        }
    }
}

function Install-Binary {
    param(
        [string]$DownloadUrl,
        [string]$Version,
        [int]$Size,
        [string]$AssetId,
        [string]$AssetName
    )
    
    $isZipFile = $AssetName -match "\.zip$"
    $tempFile = if ($isZipFile) {
        [System.IO.Path]::GetTempFileName() + ".zip"
    } else {
        [System.IO.Path]::GetTempFileName()
    }
    $finalPath = Join-Path -Path $InstallPath -ChildPath $ExeName
    
    try {
        Write-Info "Downloading nn-cli $Version..."
        Write-Info "Size: $([Math]::Round($Size / 1024 / 1024, 2)) MB"
        Write-Info "This may take a moment..."
        
        # Use Github API asset download endpoint for private repositories
        $username = $env:GITHUB_USERNAME
        $token = $env:GITHUB_TOKEN
        
        $apiDownloadUrl = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/assets/$AssetId"
        Write-Info "Using Github API asset download"
        
        $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${token}"))
        $downloadParams = @{
            Uri             = $apiDownloadUrl
            OutFile         = $tempFile
            UseBasicParsing = $true
            Headers         = @{
                "Authorization" = "Basic $auth"
                "Accept"        = "application/octet-stream"
                "User-Agent"    = "nn-cli-installer/1.0"
            }
        }
        
        # Retry logic for network failures
        $retryDelay = 2
        $retryCount = 0
        $downloadSuccess = $false
        
        Write-Debug-Info "Using max retries: $MaxRetries"
        
        while ($retryCount -lt $MaxRetries -and -not $downloadSuccess) {
            try {
                if ($retryCount -gt 0) {
                    Write-Info "Retry attempt $retryCount of $($MaxRetries - 1)..."
                    Start-Sleep -Seconds $retryDelay
                    $retryDelay *= 2  # Exponential backoff
                }
                
                # Inject network failure for testing
                if ($InjectNetworkFail) {
                    Write-Debug-Info "Injecting network failure for testing"
                    Write-Warning-Info "TESTING: Simulating network failure"
                    throw "Simulated network failure"
                }
                
                Write-Info "Starting download..."
                Invoke-WebRequest @downloadParams
                
                # Inject bad download for testing
                if ($InjectBadDownload) {
                    Write-Debug-Info "Injecting bad download for testing"
                    Write-Warning-Info "TESTING: Replacing download with HTML content"
                    $htmlContent = @"
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body>
</html>
"@
                    Set-Content -Path $tempFile -Value $htmlContent -Encoding UTF8
                }
                
                Write-Success "Download completed!"
                $downloadSuccess = $true
            }
        catch [System.Net.WebException] {
            $errorMessage = $_.Exception.Message
            $statusCode = $_.Exception.Response.StatusCode
            if ($statusCode -eq 401) {
                throw "Download failed: Authentication required. Please check your GITHUB_USERNAME and GITHUB_TOKEN."
            }
            elseif ($statusCode -eq 404) {
                throw "Download failed: Binary not found at URL. The release may have been removed."
            }
            elseif ($statusCode -eq 406) {
                throw "Download failed: Not Acceptable (406). This may be due to incompatible request headers. Try manual download from: $DownloadUrl"
            }
            elseif ($statusCode -eq 403) {
                throw "Download failed: Forbidden (403). You may not have permission to access this release. Check authentication or repository access."
            }
            else {
                throw "Download failed: HTTP $statusCode - $errorMessage"
            }
        }
        catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            $statusCode = $_.Exception.Response.StatusCode
            if ($statusCode -eq 406) {
                throw "Download failed: Not Acceptable (406). This may be due to incompatible request headers. Try manual download from: $DownloadUrl"
            }
            else {
                throw "Download failed: HTTP $statusCode - $($_.Exception.Message)"
            }
        }
            catch {
                $retryCount++
                if ($retryCount -lt $MaxRetries) {
                    Write-Warning "Download failed: $($_.Exception.Message). Retrying in $retryDelay seconds..."
                    if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
                } else {
                    throw "Download failed after $MaxRetries attempts: $($_.Exception.Message)"
                }
            }
        }
        
        if (-not (Test-Path $tempFile)) {
            throw "Download failed - temporary file not found"
        }
        
        # Validate downloaded file
        Write-Info "Validating downloaded file..."
        $fileInfo = Get-Item $tempFile
        
        # Check file size
        if ($fileInfo.Length -eq 0) {
            throw "Downloaded file is empty"
        }
        
        if ($fileInfo.Length -lt 1000) {
            throw "Downloaded file is too small ($($fileInfo.Length) bytes) - likely corrupted"
        }
        
        # Check if it's actually an executable or ZIP
        $fileBytes = [System.IO.File]::ReadAllBytes($tempFile)
        if ($fileBytes.Length -lt 2) {
            throw "Downloaded file is too small to be a valid file"
        }
        
        # Check file type based on extension
        if ($isZipFile) {
            # Check for ZIP header
            $zipHeader = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..1])
            if ($zipHeader -ne "PK") {
                Write-Warning "Downloaded file does not appear to be a valid ZIP archive"
                # Get more info about what we actually downloaded
                $firstChunk = [System.Text.Encoding]::UTF8.GetString($fileBytes[0..[Math]::Min(200, $fileBytes.Length - 1)])
                Write-Info "File starts with: $($firstChunk.Substring(0, [Math]::Min(50, $firstChunk.Length)))"
                Write-Info "Expected: ZIP archive starting with 'PK'"
                # Check if it's a text file (HTML error page, etc.)
                if ($firstChunk -match "<!DOCTYPE|<html|<HTML|<head|<body") {
                    Write-Error "Downloaded file is an HTML page instead of a binary!"
                    Write-Info "This indicates authentication or access issues."
                    Write-Info "Solutions:"
                    Write-Info "1. Check if you have access to: https://github.com/$RepoOwner/$RepoName"
                    Write-Info "2. Try downloading manually from the releases page"
                    throw "Downloaded HTML instead of binary"
                }
                # Check if it's JSON (API error response)
                if ($firstChunk -match '^\s*\{.*"message"') {
                    Write-Error "Downloaded JSON error response instead of binary!"
                    Write-Info "API Error Response:"
                    Write-Info $firstChunk
                    throw "Downloaded API error response instead of binary"
                }
                throw "Downloaded file is not a valid ZIP archive"
            }
        } else {
            # Check for PE header (Windows executable)
            $dosHeader = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..1])
            if ($dosHeader -ne "MZ") {
                Write-Warning "Downloaded file does not appear to be a Windows executable"
                # Get more info about what we actually downloaded
                $firstChunk = [System.Text.Encoding]::UTF8.GetString($fileBytes[0..[Math]::Min(200, $fileBytes.Length - 1)])
                Write-Info "File starts with: $($firstChunk.Substring(0, [Math]::Min(50, $firstChunk.Length)))"
                Write-Info "Expected: Windows PE executable starting with 'MZ'"
                # Check if it's a text file (HTML error page, etc.)
                if ($firstChunk -match "<!DOCTYPE|<html|<HTML|<head|<body") {
                    Write-Error "Downloaded file is an HTML page instead of a binary!"
                    Write-Info "This indicates authentication or access issues."
                    Write-Info "Solutions:"
                    Write-Info "1. Check if you have access to: https://github.com/$RepoOwner/$RepoName"
                    Write-Info "2. Try downloading manually from the releases page"
                    throw "Downloaded HTML instead of binary"
                }
                # Check if it's JSON (API error response)
                if ($firstChunk -match '^\s*\{.*"message"') {
                    Write-Error "Downloaded JSON error response instead of binary!"
                    Write-Info "API Error Response:"
                    Write-Info $firstChunk
                    throw "Downloaded API error response instead of binary"
                }
                throw "Downloaded file is not a valid Windows executable"
            }
        }
        
        Write-Success "File validation passed"
        
        if ($isZipFile) {
            Write-Info "Extracting ZIP archive..."
            
            # Create temp extraction directory
            $extractDir = Join-Path $env:TEMP "nn-cli-extract-$(Get-Random)"
            New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
            
            try {
                # Extract the ZIP file
                Expand-Archive -Path $tempFile -DestinationPath $extractDir -Force
                
                # Find the executable in the extracted files
                $exeFiles = @(Get-ChildItem -Path $extractDir -Filter "*.exe" -Recurse)
                
                if ($exeFiles.Count -eq 0) {
                    throw "No executable found in the ZIP archive"
                }
                
                Write-Info "Found $($exeFiles.Count) executable(s) in archive"
                
                # Look for nn.exe or nn-cli*.exe
                $nnExe = $exeFiles | Where-Object { $_.Name -match "^(nn|nn-cli.*)\.exe$" } | Select-Object -First 1
                
                if (-not $nnExe) {
                    # If no nn.exe found, use the first exe
                    $nnExe = $exeFiles[0]
                    Write-Info "Using executable: $($nnExe.Name)"
                }
                
                Write-Info "Installing to: $finalPath"
                Copy-Item $nnExe.FullName $finalPath -Force
                
                # Clean up extraction directory and temp file
                Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                # Clean up on error
                if (Test-Path $extractDir) {
                    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
                throw "Failed to extract and install from ZIP: $_"
            }
        } else {
            Write-Info "Installing to: $finalPath"
            Move-Item $tempFile $finalPath -Force
        }
        
        Write-Success "nn-cli $Version installed successfully!"
        
    }
    catch {
        Write-Error "Failed to download or install binary: $_"
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
        exit 1
    }
}

function Add-ToPath {
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    
    if ($currentPath -notlike "*$InstallPath*") {
        Write-Info "Adding $InstallPath to user PATH..."
        try {
            $newPath = "$currentPath;$InstallPath"
            [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
            Write-Success "Added to PATH. Please restart your terminal or run: `$env:PATH += ';$InstallPath'"
        }
        catch {
            Write-Warning "Failed to add to PATH automatically. Please add '$InstallPath' to your PATH manually."
        }
    }
    else {
        Write-Info "Installation directory already in PATH"
    }
}

function Test-Installation {
    $exePath = Join-Path -Path $InstallPath -ChildPath $ExeName
    try {
        Write-Info "Testing installation..."
        
        # First check if the file exists and is executable
        if (-not (Test-Path $exePath)) {
            Write-Warning "Installed binary not found at: $exePath"
            return
        }
        
        # Check file properties
        $fileInfo = Get-Item $exePath
        Write-Info "Binary size: $([Math]::Round($fileInfo.Length / 1024 / 1024, 2)) MB"
        
        # Try to run the binary
        try {
            $output = & $exePath version 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Installation test passed!"
                Write-Info "Installed version: $($output | Out-String)".Trim()
                Write-Info "Run 'nn --help' to get started"
            }
            else {
                Write-Warning "Installation test failed with exit code: $LASTEXITCODE"
                Write-Info "Output: $output"
            }
        }
        catch [System.ComponentModel.Win32Exception] {
            $errorCode = $_.Exception.NativeErrorCode
            if ($errorCode -eq 193) {
                Write-Error "Binary execution failed: The file is not a valid Win32 application"
                Write-Info "This usually means:"
                Write-Info "1. The downloaded file is corrupted"
                Write-Info "2. The binary is for a different architecture (32-bit vs 64-bit)"
                Write-Info "3. The file is not actually a Windows executable"
                Write-Info ""
                Write-Info "Try downloading manually from: https://github.com/$RepoOwner/$RepoName/releases"
            }
            else {
                Write-Warning "Could not execute binary: $($_.Exception.Message) (Error code: $errorCode)"
            }
        }
    }
    catch {
        Write-Warning "Could not test installation: $_"
    }
}

function Show-Help {
    Write-Information @"
nn-cli CLI Installer

USAGE:
    .\install.ps1 [OPTIONS]

STANDARD OPTIONS:
    -InstallPath <path>    Directory to install nn-cli (default: `$HOME\.nn\bin)
    -Force                 Force reinstallation even if already installed
    -Help                  Show this help message
    -Debug                 Enable debug output with detailed logging
    -DryRun                Show what would be done without making changes
    -Quiet                 Minimize output (errors and warnings only)

TESTING OPTIONS:
    -TestAuth              Test GitHub authentication and exit

FAILURE INJECTION OPTIONS (for testing):
    -InjectBadDownload     Download HTML instead of binary to test validation
    -InjectNetworkFail     Simulate network failure to test retry logic
    -InjectAuthFail        Use fake credentials to test authentication failure
    -MaxRetries <int>      Set custom retry count (default: 3)

EXAMPLES:
    .\install.ps1                                    # Standard installation
    .\install.ps1 -Force                             # Force reinstall
    .\install.ps1 -Debug                             # Debug mode for troubleshooting
    .\install.ps1 -DryRun                            # Preview what would happen
    .\install.ps1 -TestAuth                          # Test authentication only
    .\install.ps1 -Quiet                             # Minimal output
    .\install.ps1 -Debug -DryRun                     # Combine options
    .\install.ps1 -InstallPath "C:\tools\nn-cli"     # Custom installation path
    
    # Testing examples
    .\install.ps1 -InjectBadDownload -Debug          # Test HTML download handling
    .\install.ps1 -InjectNetworkFail -Debug          # Test retry logic
    .\install.ps1 -InjectAuthFail -Debug             # Test auth failure handling
    .\install.ps1 -MaxRetries 1 -InjectNetworkFail   # Fast test with 1 retry

REMOTE INSTALLATION:
    iex (irm 'https://raw.githubusercontent.com/NovoNordisk-OpenSource/nn-cli-installers/refs/heads/main/install.ps1')

AUTHENTICATION:
    Set these environment variables:
      `$env:GITHUB_USERNAME = 'your-github-username'
      `$env:GITHUB_TOKEN = 'your-personal-access-token'

DEBUG MODE:
    Use -Debug to get detailed information about:
    - Authentication process and headers
    - Network requests and responses
    - File operations and validations
    - Platform detection and system info

MANUAL INSTALLATION:
    If automatic installation fails, you can:
    1. Download the binary from: https://github.com/$RepoOwner/$RepoName/releases
    2. Or build from source:
       git clone https://github.com/$RepoOwner/$RepoName.git
       cd $RepoName/src
       make build-windows-amd64
       copy ../out/nn-cli/bin/nn-cli-*-windows-amd64.exe <install-path>\nn.exe
"@
}

function Test-SystemCompatibility {
    Write-Info "Checking system compatibility..."
    
    # Check OS version
    $osVersion = [System.Environment]::OSVersion
    Write-Info "OS: $($osVersion.VersionString)"
    
    # Check architecture
    $arch = [System.Environment]::Is64BitOperatingSystem
    if ($arch) {
        Write-Info "Architecture: 64-bit"
    }
    else {
        Write-Warning "Architecture: 32-bit - nn-cli requires 64-bit Windows"
        Write-Info "The nn-cli binary requires a 64-bit system"
        return $false
    }
    
    # Check if we're running in 64-bit PowerShell
    $psArch = [System.Environment]::Is64BitProcess
    if (-not $psArch) {
        Write-Warning "Running in 32-bit PowerShell on 64-bit system"
        Write-Info "This may cause compatibility issues. Consider using 64-bit PowerShell."
    }
    
    return $true
}

# Main installation logic
function Main {
    if ($Help) {
        Show-Help
        return
    }

    Write-Info "nn-cli CLI Installer"
    Write-Info "=========================="
    
    # Debug mode information
    if ($Debug) {
        Write-Debug-Info "Debug mode enabled"
        Write-Debug-Info "Standard Parameters: Force=$Force DryRun=$DryRun TestAuth=$TestAuth Quiet=$Quiet"
        Write-Debug-Info "Testing Parameters: InjectBadDownload=$InjectBadDownload InjectNetworkFail=$InjectNetworkFail InjectAuthFail=$InjectAuthFail MaxRetries=$MaxRetries"
        Write-Debug-Info "Environment: User=$env:USERNAME Home=$HOME PSVersion=$($PSVersionTable.PSVersion)"
        Write-Debug-Info "Install Path: $InstallPath"
    }
    
    # Test authentication only mode
    if ($TestAuth) {
        Write-Info "Running authentication test only..."
        if (Test-Authentication) {
            Write-Success "Authentication test completed successfully"
            return
        } else {
            Write-Error "Authentication test failed"
            exit 1
        }
    }

    # Check system compatibility
    if (-not (Test-SystemCompatibility)) {
        Write-Error "System compatibility check failed"
        exit 1
    }
    
    # Check if already installed
    $currentVersion = Test-ExistingInstallation
    
    # Get latest release info
    $release = Get-LatestRelease
    Write-Info "Latest version: $($release.Version)"
    
    # Check if we need to update
    if ($currentVersion -eq $release.Version) {
        if (-not $Force) {
            Write-Success "Already have the latest version ($currentVersion)"
            return
        }
        else {
            Write-Info "Force flag detected: proceeding with reinstallation of nn-cli $($release.Version)"
        }
    }
    
    if ($currentVersion) {
        Write-Info "Updating from $currentVersion to $($release.Version)"
    }
    
    # Dry run mode - show what would be done
    if ($DryRun) {
        Write-Info "DRY RUN MODE - No actual changes will be made"
        Write-Info "Would create installation directory: $InstallPath"
        Write-Info "Would download binary: $($release.AssetName)"
        Write-Info "Would install to: $(Join-Path $InstallPath $ExeName)"
        Write-Info "Would add to PATH if needed"
        Write-Success "Dry run completed successfully"
        return
    }
    
    # Create installation directory
    Write-Debug-Info "Creating installation directory..."
    New-InstallDirectory
    
    # Download and install
    Write-Debug-Info "Starting binary download and installation..."
    Install-Binary -DownloadUrl $release.DownloadUrl -Version $release.Version -Size $release.Size -AssetId $release.AssetId -AssetName $release.AssetName
    
    # Add to PATH
    Add-ToPath
    
    # Test installation
    Test-Installation
    
    Write-Success "Installation completed successfully!"

    # Update current session PATH to make nn available immediately
    $currentSessionPath = $env:PATH
    if ($currentSessionPath -notlike "*$InstallPath*") {
        $env:PATH = "$currentSessionPath;$InstallPath"
        Write-Success "Current session PATH updated - nn command is now available!"
    }

    Write-Info ""
    Write-Info "[OK] Ready to use! The nn command is available in this session."
    Write-Info "Next steps:"
    Write-Info "1. Run 'nn --help' to see available commands"
    Write-Info "2. Run 'nn init' to initialize your project"
    Write-Info ""
    Write-Info "Note: For new terminal sessions, the PATH is already configured."
}

# Execute main function
Main