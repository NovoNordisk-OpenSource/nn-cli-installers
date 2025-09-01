#!/bin/bash
set -e

# Check if we have required commands
check_requirements() {
    local missing_commands=""
    
    # Check for required commands
    for cmd in uname grep sed awk head tail cut tr; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands="$missing_commands $cmd"
        fi
    done
    
    # Check for download commands
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        missing_commands="$missing_commands curl-or-wget"
    fi
    
    # Check for file commands
    if ! command -v file >/dev/null 2>&1; then
        missing_commands="$missing_commands file"
    fi
    
    if [ -n "$missing_commands" ]; then
        echo "[ERROR] Missing required commands:$missing_commands"
        echo "Please install the missing commands and try again"
        exit 1
    fi
}

# Constants
REPO_OWNER="nn-gdai"
REPO_NAME="nn-cli"
INSTALL_DIR="${HOME}/.nn/bin"
BINARY_NAME="nn"

# Functions (will be redefined later with enhanced logging)

# Detect platform with fallbacks
detect_platform() {
    local os=""
    local arch=""
    
    # Try different methods to get OS
    if command -v uname >/dev/null 2>&1; then
        os=$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')
    fi
    
    # Fallback OS detection
    if [ -z "$os" ]; then
        if [ -f /etc/os-release ]; then
            os="linux"
        elif [ -f /System/Library/CoreServices/SystemVersion.plist ]; then
            os="darwin"
        else
            os="unknown"
        fi
    fi
    
    # Try different methods to get architecture
    if command -v uname >/dev/null 2>&1; then
        arch=$(uname -m 2>/dev/null)
    fi
    
    # Fallback architecture detection
    if [ -z "$arch" ]; then
        if command -v arch >/dev/null 2>&1; then
            arch=$(arch 2>/dev/null)
        elif [ -n "$HOSTTYPE" ]; then
            arch="$HOSTTYPE"
        else
            arch="unknown"
        fi
    fi
    
    # Map architecture names
    case "$arch" in
        x86_64|amd64)
            arch="amd64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        armv7*)
            arch="arm"
            ;;
        i386|i686)
            arch="386"
            ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    # Map OS names
    case "$os" in
        linux)
            echo "nn-linux-$arch"
            ;;
        darwin)
            echo "nn-darwin-$arch"
            ;;
        freebsd)
            echo "nn-freebsd-$arch"
            ;;
        openbsd)
            echo "nn-openbsd-$arch"
            ;;
        *)
            error "Unsupported operating system: $os"
            exit 1
            ;;
    esac
}

# Test authentication without downloading
test_authentication() {
    info "Testing GitHub authentication..."
    debug "Username: $GITHUB_USERNAME"
    debug "Token present: $([ -n "$GITHUB_TOKEN" ] && echo "yes" || echo "no")"
    
    local auth_string=$(get_auth_headers)
    local api_url="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest"
    
    debug "API URL: $api_url"
    debug "Auth string length: ${#auth_string}"
    
    if command -v curl >/dev/null 2>&1; then
        local response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
            -H "Authorization: Basic $auth_string" \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$api_url" 2>/dev/null)
        
        local http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
        debug "HTTP response code: $http_code"
        
        if [ "$http_code" = "200" ]; then
            success "Authentication test passed!"
            local tag_name=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//' | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
            info "Latest release: $tag_name"
            return 0
        else
            error "Authentication test failed (HTTP $http_code)"
            if [ -n "$DEBUG_MODE" ]; then
                info "Response preview:"
                echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//' | head -10
            fi
            return 1
        fi
    else
        error "curl not available for authentication test"
        return 1
    fi
}

# Get authentication headers (required for internal org)
get_auth_headers() {
    local username="$GITHUB_USERNAME"
    local token="$GITHUB_TOKEN"
    
    debug "Getting auth headers for user: ${username:-<not set>}"
    
    # Inject authentication failure for testing
    if [ -n "$INJECT_AUTH_FAIL" ]; then
        debug "Injecting authentication failure for testing"
        username="fake-user"
        token="fake-token"
        warning "TESTING: Using fake credentials to simulate auth failure"
    fi
    
    # Note: Authentication check is now done in main() before calling get_latest_release
    # This function assumes credentials are available
    
    # Create base64 encoded auth string
    # Make sure there are no newlines in the output
    local auth_string=$(printf "%s:%s" "$username" "$token" | base64 | tr -d '\n')
    debug "Auth string created (length: ${#auth_string})"
    echo "$auth_string"
}

# Get latest release information
get_latest_release() {
    local api_url="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest"
    local response=""
    local http_code=""
    local auth_string=$(get_auth_headers)
    
    debug "Getting latest release from: $api_url"
    debug "Auth string length: ${#auth_string}"
    
    if command -v curl >/dev/null 2>&1; then
        debug "Using curl for API request"
        response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
            -H "Authorization: Basic $auth_string" \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$api_url")
        http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
        response=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
        debug "HTTP response code: $http_code"
        if [ -n "$DEBUG_MODE" ] && [ "$http_code" != "200" ]; then
            debug "Response preview: $(echo "$response" | head -c 200)"
        fi
    elif command -v wget >/dev/null 2>&1; then
        debug "Using wget for API request"
        if wget --user="$GITHUB_USERNAME" --password="$GITHUB_TOKEN" -qO- "$api_url" >/tmp/release_response 2>/dev/null; then
            response=$(cat /tmp/release_response)
            http_code="200"
            rm -f /tmp/release_response
        else
            http_code="404"
        fi
        debug "HTTP response code: $http_code"
    else
        error "Neither curl nor wget is available"
        exit 1
    fi
    
    # Return response (let caller handle errors)
    echo "$response"
}

# Download file with retry logic
download_file() {
    local asset_id=$1
    local output=$2
    local auth_string=$(get_auth_headers)
    local max_retries=3
    local retry_delay=2
    
    # Use GitHub API asset download endpoint for private repositories
    local api_url="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/assets/$asset_id"
    info "Using GitHub API asset download"
    info "API URL: $api_url"
    
    # Try download once (retry logic is handled in main function)
    if command -v curl >/dev/null 2>&1; then
        # Download the file using GitHub API with follow redirects
        info "Downloading asset..."
        
        # Inject network failure for testing
        if [ -n "$INJECT_NETWORK_FAIL" ]; then
            debug "Injecting network failure for testing"
            warning "TESTING: Simulating network failure"
            return 1
        fi
        
        # Use -S for show errors, -s for silent, -L for follow redirects
        # Capture both stderr and HTTP status
        local curl_stderr=$(mktemp)
        local http_status=$(curl -L -S -s -w "%{http_code}" \
            -H "Authorization: Basic $auth_string" \
            -H "Accept: application/octet-stream" \
            -H "User-Agent: nn-cli-installer/1.0" \
            -o "$output" \
            "$api_url" 2>"$curl_stderr")
        
        # Check for curl command failure
        if [ $? -ne 0 ]; then
            error "curl command failed"
            if [ -f "$curl_stderr" ] && [ -s "$curl_stderr" ]; then
                info "Error details:"
                cat "$curl_stderr"
            fi
            rm -f "$curl_stderr" "$output"
            return 1
        fi
        
        # GitHub redirects asset downloads, so we might get 302/301 initially
        # The -L flag follows the redirect, final status should be 200
        # However, curl returns the last HTTP status with -w "%{http_code}"
        if [ "$http_status" != "200" ] && [ "$http_status" != "302" ] && [ "$http_status" != "301" ]; then
            error "Download failed with HTTP status: $http_status"
            if [ -f "$curl_stderr" ] && [ -s "$curl_stderr" ]; then
                info "Curl error output:"
                cat "$curl_stderr"
            fi
            # Check if we got an HTML error page
            if [ -f "$output" ] && head -c 100 "$output" | grep -qi "<!doctype\|<html"; then
                info "Received HTML error page. First 500 bytes:"
                head -c 500 "$output"
            fi
            rm -f "$curl_stderr" "$output"
            return 1
        fi
        
        rm -f "$curl_stderr"
        
        # Inject bad download for testing
        if [ -n "$INJECT_BAD_DOWNLOAD" ]; then
            debug "Injecting bad download for testing"
            warning "TESTING: Replacing download with HTML content"
            cat > "$output" << 'EOF'
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body>
</html>
EOF
        fi
        
        # Debug: Check what we actually downloaded
        # Cross-platform file size detection
        local file_size=""
        if command -v stat >/dev/null 2>&1; then
            # Try GNU stat first, then BSD stat
            file_size=$(stat -c%s "$output" 2>/dev/null || stat -f%z "$output" 2>/dev/null || echo "")
        fi
        if [ -z "$file_size" ] && command -v wc >/dev/null 2>&1; then
            # Fallback to wc
            file_size=$(wc -c < "$output" 2>/dev/null | tr -d ' ')
        fi
        if [ -z "$file_size" ]; then
            file_size="0"
        fi
        info "Downloaded file size: $file_size bytes"
        info "File type: $(file -b "$output" 2>/dev/null || echo 'unknown')"
        
        # Check the first few bytes to see what type of file it is  
        if [ "$file_size" -lt 10000 ]; then
            info "Small file detected, showing hex dump:"
            hexdump -C "$output" | head -5
        fi
        
    elif command -v wget >/dev/null 2>&1; then
        # wget with GitHub API is more complex, but works
        if ! wget --user="$GITHUB_USERNAME" --password="$GITHUB_TOKEN" --header="Accept: application/octet-stream" --header="User-Agent: nn-cli-installer/1.0" -O "$output" "$api_url"; then
            return 1
        fi
    else
        error "Neither curl nor wget is available"
        return 1
    fi
    
    # Validate downloaded file
    if [ ! -f "$output" ]; then
        error "Download failed - file not created"
        return 1
    fi
    
    # Cross-platform file size detection
    local file_size=""
    if command -v stat >/dev/null 2>&1; then
        file_size=$(stat -c%s "$output" 2>/dev/null || stat -f%z "$output" 2>/dev/null || echo "")
    fi
    if [ -z "$file_size" ] && command -v wc >/dev/null 2>&1; then
        file_size=$(wc -c < "$output" 2>/dev/null | tr -d ' ')
    fi
    if [ -z "$file_size" ]; then
        file_size="0"
    fi
    
    # Binary should be at least 1MB, anything smaller is suspicious
    if [ "$file_size" -lt 1000000 ]; then
        warning "Downloaded file is suspiciously small ($file_size bytes)"
        
        # Extra validation for small files
        if [ "$file_size" -lt 10000 ]; then
            error "File too small to be a valid binary ($file_size bytes)"
            info "This usually indicates an authentication or download error"
            rm -f "$output"
            return 1
        fi
    fi
    
    # Check if file starts with HTML or is too small
    if head -c 20 "$output" | grep -qi "<!doctype\|<html"; then
        error "Downloaded file appears to be HTML instead of binary"
        info "This indicates authentication issues or incorrect URL"
        info "HTML content preview:"
        head -c 500 "$output"
        info ""
        info "Asset ID used: $asset_id"
        info "API URL: $api_url"
        rm -f "$output"
        return 1
    fi
    
    # Additional check for JSON error responses
    if head -c 1 "$output" | grep -q "{"; then
        if head -c 100 "$output" | grep -q '"message"'; then
            error "Downloaded JSON error response instead of binary"
            info "Error response:"
            head -c 500 "$output"
            rm -f "$output"
            return 1
        fi
    fi
    
    # Success - return 0
    return 0
}

# Check if binary exists and get version
check_existing_installation() {
    local binary_path="$INSTALL_DIR/$BINARY_NAME"
    
    if [ -f "$binary_path" ] && [ -x "$binary_path" ]; then
        "$binary_path" version 2>/dev/null | grep "Version:" | awk '{print $2}' || echo "unknown"
    else
        echo ""
    fi
}

# Add to PATH
add_to_path() {
    local shell_config=""
    local detected_shell=""
    
    # Determine shell config file
    if [ -n "$ZSH_VERSION" ]; then
        # Running in zsh
        shell_config="$HOME/.zshrc"
        detected_shell="zsh"
    elif [ -n "$BASH_VERSION" ]; then
        # Running in bash
        shell_config="$HOME/.bashrc"
        detected_shell="bash"
    else
        # Not running in bash or zsh, need to detect default shell
        if [ -n "$SHELL" ]; then
            case "$SHELL" in
                */zsh)
                    shell_config="$HOME/.zshrc"
                    detected_shell="zsh"
                    ;;
                */bash)
                    shell_config="$HOME/.bashrc"
                    detected_shell="bash"
                    ;;
                */fish)
                    shell_config="$HOME/.config/fish/config.fish"
                    detected_shell="fish"
                    ;;
                *)
                    # Default to profile for unknown shells
                    shell_config="$HOME/.profile"
                    detected_shell="unknown"
                    ;;
            esac
        else
            # Last resort: check which files exist (common on macOS)
            if [ -f "$HOME/.zshrc" ]; then
                shell_config="$HOME/.zshrc"
                detected_shell="zsh"
            elif [ -f "$HOME/.bash_profile" ]; then
                shell_config="$HOME/.bash_profile"
                detected_shell="bash"
            elif [ -f "$HOME/.bashrc" ]; then
                shell_config="$HOME/.bashrc"
                detected_shell="bash"
            else
                shell_config="$HOME/.profile"
                detected_shell="profile"
            fi
        fi
    fi
    
    # Special handling for macOS
    if [ "$(uname -s)" = "Darwin" ]; then
        # macOS uses .bash_profile instead of .bashrc for login shells
        if [ "$detected_shell" = "bash" ] && [ -f "$HOME/.bash_profile" ]; then
            shell_config="$HOME/.bash_profile"
        fi
        # macOS Catalina and later use zsh by default
        # If no config file exists yet, create the appropriate one
        if [ ! -f "$shell_config" ]; then
            # Check the default shell
            local default_shell=$(dscl . -read /Users/$USER UserShell 2>/dev/null | awk '{print $2}')
            case "$default_shell" in
                */zsh)
                    shell_config="$HOME/.zshrc"
                    detected_shell="zsh"
                    ;;
                */bash)
                    shell_config="$HOME/.bash_profile"
                    detected_shell="bash"
                    ;;
                *)
                    # Default to zsh on modern macOS
                    shell_config="$HOME/.zshrc"
                    detected_shell="zsh"
                    ;;
            esac
        fi
    fi
    
    debug "Detected shell: $detected_shell"
    debug "Shell config file: $shell_config"
    
    # Check if already in PATH
    if echo "$PATH" | grep -q "$INSTALL_DIR"; then
        info "Installation directory already in PATH"
        return
    fi
    
    # Create shell config file if it doesn't exist
    if [ ! -f "$shell_config" ]; then
        debug "Creating shell config file: $shell_config"
        touch "$shell_config"
    fi
    
    # Add to shell config
    if [ "$detected_shell" = "fish" ]; then
        # Fish shell has different syntax
        if ! grep -q "$INSTALL_DIR" "$shell_config"; then
            echo "" >> "$shell_config"
            echo "# Added by nn-cli installer" >> "$shell_config"
            echo "set -gx PATH \$PATH $INSTALL_DIR" >> "$shell_config"
            success "Added to PATH in $shell_config"
            warning "Please restart your terminal or run: set -gx PATH \$PATH $INSTALL_DIR"
        fi
    else
        # Bash/Zsh/Sh syntax
        if ! grep -q "$INSTALL_DIR" "$shell_config"; then
            echo "" >> "$shell_config"
            echo "# Added by nn-cli installer" >> "$shell_config"
            echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$shell_config"
            success "Added to PATH in $shell_config"
            warning "Please restart your terminal or run: export PATH=\"\$PATH:$INSTALL_DIR\""
        fi
    fi
    
    # Additional instructions for macOS users
    if [ "$(uname -s)" = "Darwin" ]; then
        info "Note for macOS users:"
        info "- The PATH has been added to $shell_config"
        if [ "$detected_shell" = "zsh" ]; then
            info "- For iTerm2: Changes will take effect in new tabs/windows"
            info "- For Terminal.app: Restart the application"
        elif [ "$detected_shell" = "bash" ]; then
            info "- For iTerm2: Ensure 'Login shell' is checked in Preferences > Profiles > General"
            info "- For Terminal.app: Should work after restart"
        fi
    fi
}

# Test installation
test_installation() {
    local binary_path="$INSTALL_DIR/$BINARY_NAME"
    
    if [ -f "$binary_path" ] && [ -x "$binary_path" ]; then
        info "Testing installation..."
        if "$binary_path" version >/dev/null 2>&1; then
            success "Installation test passed!"
            # Show the installed version
            local installed_version=$("$binary_path" version 2>/dev/null | head -1)
            if [ -n "$installed_version" ]; then
                info "Installed: $installed_version"
            fi
        else
            warning "Installation test failed"
            debug "Binary exists but 'version' command failed"
        fi
    else
        error "Binary not found or not executable: $binary_path"
        exit 1
    fi
}

show_help() {
    cat << 'EOF'
nn-cli CLI Installer

USAGE:
    ./install.sh [OPTIONS]

STANDARD OPTIONS:
    --help          Show this help message
    --force         Force reinstallation even if already installed
    --debug         Enable debug output with detailed logging
    --dry-run       Show what would be done without making changes
    --quiet         Minimize output (errors and warnings only)

TESTING OPTIONS:
    --test-auth              Test GitHub authentication and exit

FAILURE INJECTION OPTIONS (for testing):
    --inject-bad-download    Download HTML instead of binary to test validation
    --inject-network-fail    Simulate network failure to test retry logic
    --inject-auth-fail       Use fake credentials to test authentication failure
    --max-retries N          Set custom retry count (default: 3)

EXAMPLES:
    ./install.sh                           # Standard installation
    ./install.sh --force                   # Force reinstall
    ./install.sh --debug                   # Debug mode for troubleshooting
    ./install.sh --dry-run                 # Preview what would happen
    ./install.sh --test-auth               # Test authentication only
    ./install.sh --quiet                   # Minimal output
    ./install.sh --debug --dry-run         # Combine options
    
    # Testing examples
    ./install.sh --inject-bad-download --debug    # Test HTML download handling
    ./install.sh --inject-network-fail --debug    # Test retry logic
    ./install.sh --inject-auth-fail --debug       # Test auth failure handling
    ./install.sh --max-retries 1 --inject-network-fail  # Fast test with 1 retry

AUTHENTICATION:
    For private repositories, set these environment variables:
      export GITHUB_USERNAME="your-github-username"
      export GITHUB_TOKEN="your-personal-access-token"

DEBUG MODE:
    Use --debug to get detailed information about:
    - Authentication process and headers
    - Network requests and responses
    - File operations and validations
    - Platform detection and system info

MANUAL INSTALLATION:
    If automatic installation fails, you can:
    1. Download the binary from: https://github.com/$REPO_OWNER/$REPO_NAME/releases
    2. Or build from source:
       git clone https://github.com/$REPO_OWNER/$REPO_NAME.git
       cd $REPO_NAME/src
       make build
       cp ../bin/nn ~/.nn-cli/
EOF
}

# Global variables for testing parameters
DEBUG_MODE=""
DRY_RUN_MODE=""
TEST_AUTH_ONLY=""
QUIET_MODE=""
FORCE_INSTALL=""

# Failure injection testing parameters
INJECT_BAD_DOWNLOAD=""
INJECT_NETWORK_FAIL=""
INJECT_AUTH_FAIL=""
MAX_RETRIES="3"

# Parse command line arguments
parse_arguments() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --help)
                show_help
                exit 0
                ;;
            --debug)
                DEBUG_MODE="1"
                ;;
            --dry-run)
                DRY_RUN_MODE="1"
                ;;
            --test-auth)
                TEST_AUTH_ONLY="1"
                ;;
            --quiet)
                QUIET_MODE="1"
                ;;
            --force)
                FORCE_INSTALL="1"
                ;;
            --inject-bad-download)
                INJECT_BAD_DOWNLOAD="1"
                ;;
            --inject-network-fail)
                INJECT_NETWORK_FAIL="1"
                ;;
            --inject-auth-fail)
                INJECT_AUTH_FAIL="1"
                ;;
            --max-retries)
                shift
                if [ $# -eq 0 ] || ! echo "$1" | grep -q "^[0-9][0-9]*$"; then
                    error "--max-retries requires a positive number"
                    exit 1
                fi
                MAX_RETRIES="$1"
                ;;
            --max-retries=*)
                MAX_RETRIES="${1#--max-retries=}"
                if ! echo "$MAX_RETRIES" | grep -q "^[0-9][0-9]*$"; then
                    error "--max-retries requires a positive number"
                    exit 1
                fi
                ;;
            *)
                error "Unknown parameter: $1"
                info "Use --help to see available options"
                exit 1
                ;;
        esac
        shift
    done
}

# Enhanced logging functions
debug() {
    if [ -n "$DEBUG_MODE" ]; then
        echo "[DEBUG] $1" >&2
    fi
}

info() {
    if [ -z "$QUIET_MODE" ]; then
        echo "[INFO] $1"
    fi
}

success() {
    if [ -z "$QUIET_MODE" ]; then
        echo "[OK] $1"
    fi
}

warning() {
    echo "[WARN] $1"
}

error() {
    echo "[ERROR] $1"
}

# Main installation function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    info "nn-cli CLI Installer"
    info "=========================="
    
    # Debug mode information
    if [ -n "$DEBUG_MODE" ]; then
        debug "Debug mode enabled"
        debug "Parameters: DRY_RUN=$DRY_RUN_MODE TEST_AUTH=$TEST_AUTH_ONLY QUIET=$QUIET_MODE FORCE=$FORCE_INSTALL"
        debug "Environment: USER=${USER:-unknown} HOME=${HOME:-unknown} PWD=$PWD"
    fi
    
    # Test authentication only mode
    if [ -n "$TEST_AUTH_ONLY" ]; then
        info "Running authentication test only..."
        if test_authentication; then
            success "Authentication test completed successfully"
            exit 0
        else
            error "Authentication test failed"
            exit 1
        fi
    fi
    
    # Check system requirements
    debug "Checking system requirements..."
    check_requirements
    
    # Detect platform
    debug "Detecting platform..."
    local platform_binary=$(detect_platform)
    info "Detected platform: $platform_binary"
    
    # Check existing installation
    local current_version=$(check_existing_installation)
    
    # Check authentication before attempting to fetch release
    if [ -z "$GITHUB_USERNAME" ] || [ -z "$GITHUB_TOKEN" ]; then
        error "GitHub authentication required to access nn-cli releases"
        info ""
        info "Please set these environment variables before running the installer:"
        info "  export GITHUB_USERNAME=\"your-github-username\""
        info "  export GITHUB_TOKEN=\"your-personal-access-token\""
        info ""
        info "Example:"
        info "  export GITHUB_USERNAME=\"john.doe\""
        info "  export GITHUB_TOKEN=\"ghp_xxxxxxxxxxxxx\""
        info ""
        info "Then run the installer again."
        exit 1
    fi
    
    info "Using GitHub authentication for $GITHUB_USERNAME"
    
    # Get latest release
    info "Fetching latest release information..."
    local release_json=$(get_latest_release)
    
    # Check if we got an error response
    if [ -z "$release_json" ]; then
        error "Failed to get release information"
        exit 1
    fi
    
    if echo "$release_json" | grep -q '"message".*"Not Found"'; then
        error "Failed to access repository releases."
        info ""
        if [ -n "$GITHUB_USERNAME" ]; then
            info "Current authentication: $GITHUB_USERNAME"
            info ""
            info "This error usually means:"
            info "1. Invalid GitHub credentials (wrong username or token)"
            info "2. Token lacks 'repo' scope for private repositories"
            info "3. You don't have access to this repository"
            info ""
            info "Please verify:"
            info "- Your GitHub username is correct"
            info "- Your personal access token is valid"
            info "- Token has 'repo' scope enabled"
            info "- You have access to: https://github.com/$REPO_OWNER/$REPO_NAME"
        else
            info "No GitHub authentication detected."
            info ""
            info "For private repositories, you must set:"
            info "  export GITHUB_USERNAME=\"your-github-username\""
            info "  export GITHUB_TOKEN=\"your-personal-access-token\""
        fi
        info ""
        info "To create a new token:"
        info "1. Go to https://github.com/settings/tokens"
        info "2. Click 'Generate new token (classic)'"
        info "3. Select 'repo' scope"
        info "4. Copy the token and set it as GITHUB_TOKEN"
        exit 1
    fi
    
    # Check for other authentication errors
    if echo "$release_json" | grep -q '"message".*"Bad credentials"'; then
        error "Authentication failed: Bad credentials"
        info ""
        info "Your GitHub token is invalid or expired."
        info "Please generate a new personal access token at:"
        info "https://github.com/settings/tokens"
        exit 1
    fi
    
    if echo "$release_json" | grep -q '"message".*"API rate limit exceeded"'; then
        error "GitHub API rate limit exceeded"
        info ""
        info "Please wait a while before trying again, or authenticate with valid credentials."
        exit 1
    fi
    
    # Parse release information
    local tag_name=$(echo "$release_json" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    
    if [ -z "$tag_name" ]; then
        error "Could not parse release information"
        if [ -n "$DEBUG_MODE" ]; then
            debug "Response length: ${#release_json}"
            debug "First 500 characters:"
            echo "$release_json" | head -c 500
            debug ""
            debug "Checking for JSON structure:"
            if echo "$release_json" | head -c 1 | grep -q "{"; then
                debug "Response appears to be JSON"
                debug "Looking for tag_name field:"
                echo "$release_json" | grep -o '"[^"]*"' | grep -C 2 "tag_name" || echo "No tag_name field found"
            else
                debug "Response does not appear to be valid JSON"
            fi
        else
            info "This usually indicates a problem with the GitHub API response."
            info "Run with --debug flag for more information."
        fi
        exit 1
    fi
    
    # Find the asset ID for the platform binary
    # Try exact match first
    local asset_line=$(echo "$release_json" | grep -A2 -B2 "\"name\".*$platform_binary\"" | head -10)
    local asset_id=$(echo "$asset_line" | grep '"id"' | head -1 | sed 's/.*"id": *\([0-9]*\).*/\1/')
    
    if [ -z "$asset_id" ]; then
        # Try to find versioned binary (e.g., nn-cli-0.0.17-linux-amd64)
        local os_arch=$(echo "$platform_binary" | sed 's/^nn-//')
        asset_line=$(echo "$release_json" | grep -A2 -B2 "\"name\".*nn-cli-.*$os_arch" | head -10)
        asset_id=$(echo "$asset_line" | grep '"id"' | head -1 | sed 's/.*"id": *\([0-9]*\).*/\1/')
    fi
    
    if [ -z "$asset_id" ]; then
        # Try with tar.gz extension
        asset_line=$(echo "$release_json" | grep -A2 -B2 "\"name\".*nn-cli-.*$os_arch.*tar\.gz" | head -10)
        asset_id=$(echo "$asset_line" | grep '"id"' | head -1 | sed 's/.*"id": *\([0-9]*\).*/\1/')
    fi
    
    if [ -z "$asset_id" ]; then
        # Try alternate naming patterns
        local os=$(echo "$platform_binary" | cut -d'-' -f2)
        local arch=$(echo "$platform_binary" | cut -d'-' -f3)
        
        # Try nn-cli-version-os-arch pattern
        asset_line=$(echo "$release_json" | grep -A2 -B2 "\"name\".*nn-cli-.*$os.*$arch" | head -10)
        asset_id=$(echo "$asset_line" | grep '"id"' | head -1 | sed 's/.*"id": *\([0-9]*\).*/\1/')
    fi
    
    if [ -z "$asset_id" ]; then
        error "Could not find asset ID for $platform_binary"
        info "Available assets:"
        echo "$release_json" | grep '"name"' | sed 's/.*"name": *"\([^"]*\)".*/  - \1/'
        exit 1
    fi
    
    # Extract actual binary name for info
    local actual_binary_name=$(echo "$asset_line" | grep '"name"' | head -1 | sed 's/.*"name": *"\([^"]*\)".*/\1/')
    if [ -n "$actual_binary_name" ] && [ "$actual_binary_name" != "$platform_binary" ]; then
        info "Found binary: $actual_binary_name"
    fi
    
    info "Latest version: $tag_name"
    
    # Check if update needed  
    if [ -n "$current_version" ] && [ -z "$FORCE_INSTALL" ]; then
        if [ "$current_version" = "$tag_name" ]; then
            success "Already have the latest version ($current_version)"
            exit 0
        else
            info "Updating from $current_version to $tag_name"
        fi
    elif [ -n "$current_version" ]; then
        info "Current version: $current_version"
        info "Latest version: $tag_name"
        info "Force reinstalling..."
    fi
    
    # Dry run mode - show what would be done
    if [ -n "$DRY_RUN_MODE" ]; then
        info "DRY RUN MODE - No actual changes will be made"
        info "Would create installation directory: $INSTALL_DIR"
        info "Would download binary: $asset_name"
        info "Would install to: $INSTALL_DIR/$BINARY_NAME"
        info "Would add to PATH if needed"
        success "Dry run completed successfully"
        exit 0
    fi
    
    # Create installation directory
    info "Creating installation directory: $INSTALL_DIR"
    debug "Creating directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    
    # Download binary with retry logic
    local temp_file=$(mktemp)
    local max_retries="$MAX_RETRIES"
    local retry_count=0
    local retry_delay=2
    
    debug "Using max retries: $max_retries"
    
    while [ $retry_count -lt $max_retries ]; do
        if [ $retry_count -gt 0 ]; then
            info "Retry attempt $retry_count of $((max_retries - 1))..."
            sleep $retry_delay
            retry_delay=$((retry_delay * 2))  # Exponential backoff
        fi
        
        if download_file "$asset_id" "$temp_file" 2>/dev/null; then
            info "Download successful"
            break
        else
            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                warning "Download failed, retrying in $retry_delay seconds..."
                rm -f "$temp_file"
            else
                error "Download failed after $max_retries attempts"
                rm -f "$temp_file"
                exit 1
            fi
        fi
    done
    
    # Install binary
    info "Installing to: $INSTALL_DIR/$BINARY_NAME"
    
    # Check if it's a tar.gz file and extract it
    if echo "$actual_binary_name" | grep -q "\.tar\.gz$"; then
        info "Extracting tar.gz archive..."
        
        # First verify it's actually a gzipped tar file
        if ! gzip -t "$temp_file" 2>/dev/null; then
            error "Downloaded file is not a valid gzip archive"
            info "File type check:"
            file "$temp_file"
            info "First 100 bytes:"
            hexdump -C "$temp_file" | head -5
            rm -f "$temp_file"
            exit 1
        fi
        
        local temp_dir=$(mktemp -d)
        if ! tar -xzf "$temp_file" -C "$temp_dir" 2>/dev/null; then
            error "Failed to extract tar.gz archive"
            rm -rf "$temp_dir"
            rm -f "$temp_file"
            exit 1
        fi
        
        # Find the binary in the extracted files
        local extracted_binary=$(find "$temp_dir" -name "nn" -type f | head -1)
        if [ -z "$extracted_binary" ]; then
            extracted_binary=$(find "$temp_dir" -name "nn-*" -type f | head -1)
        fi
        
        if [ -n "$extracted_binary" ]; then
            mv "$extracted_binary" "$INSTALL_DIR/$BINARY_NAME"
            chmod +x "$INSTALL_DIR/$BINARY_NAME"
            rm -rf "$temp_dir"
            rm -f "$temp_file"
        else
            error "Could not find binary in extracted archive"
            info "Archive contents:"
            find "$temp_dir" -type f
            rm -rf "$temp_dir"
            rm -f "$temp_file"
            exit 1
        fi
    else
        # Direct binary file
        mv "$temp_file" "$INSTALL_DIR/$BINARY_NAME"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    success "nn-cli $tag_name installed successfully!"
    
    # Add to PATH
    add_to_path
    
    # Test installation
    test_installation
    
    success "Installation completed successfully!"
    
    # Update current session PATH to make nn available immediately
    if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
        export PATH="$PATH:$INSTALL_DIR"
        success "Current session PATH updated - nn command is now available!"
        
        # Provide shell-specific instructions
        info ""
        info "[OK] Ready to use! The nn command is available in this session."
        info ""
        info "To make nn available in new terminal sessions:"
        
        # Get the shell config file that was updated
        local shell_config_updated=""
        if [ -f "$HOME/.zshrc" ] && grep -q "$INSTALL_DIR" "$HOME/.zshrc" 2>/dev/null; then
            shell_config_updated="$HOME/.zshrc"
        elif [ -f "$HOME/.bash_profile" ] && grep -q "$INSTALL_DIR" "$HOME/.bash_profile" 2>/dev/null; then
            shell_config_updated="$HOME/.bash_profile"
        elif [ -f "$HOME/.bashrc" ] && grep -q "$INSTALL_DIR" "$HOME/.bashrc" 2>/dev/null; then
            shell_config_updated="$HOME/.bashrc"
        elif [ -f "$HOME/.config/fish/config.fish" ] && grep -q "$INSTALL_DIR" "$HOME/.config/fish/config.fish" 2>/dev/null; then
            shell_config_updated="$HOME/.config/fish/config.fish"
        elif [ -f "$HOME/.profile" ] && grep -q "$INSTALL_DIR" "$HOME/.profile" 2>/dev/null; then
            shell_config_updated="$HOME/.profile"
        fi
        
        if [ -n "$shell_config_updated" ]; then
            info "  - Restart your terminal, OR"
            info "  - Run: source $shell_config_updated"
        else
            info "  - Add this to your shell configuration:"
            info "    export PATH=\"\$PATH:$INSTALL_DIR\""
        fi
    else
        info ""
        info "[OK] Ready to use! The nn command is already in your PATH."
    fi
    
    info ""
    info "Next steps:"
    info "  1. Run 'nn --help' to see available commands"
    info "  2. Run 'nn init' to initialize your project"
    info ""
    
    # Special note for macOS
    if [ "$(uname -s)" = "Darwin" ]; then
        info "macOS Terminal Tips:"
        info "  - iTerm2 users: Just open a new tab or window"
        info "  - Terminal.app users: Restart the application"
        info "  - If 'nn' command not found: run 'source $shell_config_updated'"
    fi
}

# Run main function
main "$@"