#!/bin/bash
# DevSec Installation Script v1.0.0
# Usage: curl -sSL https://raw.githubusercontent.com/victoralfred/devsec/main/install.sh | bash
# Or: curl -sSL ... | bash -s -- -v v0.1.0 -d /custom/path
#
# Options:
#   -v VERSION    Install specific version (default: latest)
#   -d DIR        Installation directory (default: /usr/local/bin)
#   -f            Force overwrite existing installation
#   -s            Skip scanner dependency prompts
#   -h            Show help

set -euo pipefail

INSTALL_SCRIPT_VERSION="1.0.0"
REPO="victoralfred/devsec"
BINARY_NAME="devsec"
DEFAULT_INSTALL_DIR="/usr/local/bin"
CLEANUP_DIR=""

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
VERSION=""
INSTALL_DIR=""
FORCE=false
SKIP_SCANNERS=false

# Utility functions
info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

success() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

header() {
    printf "\n${BOLD}${CYAN}%s${NC}\n" "$1"
    printf '%*s\n' "${#1}" '' | tr ' ' '-'
}

# Show help
show_help() {
    cat << EOF
DevSec Installation Script v${INSTALL_SCRIPT_VERSION}

Usage: curl -sSL https://raw.githubusercontent.com/victoralfred/devsec/main/install.sh | bash
       curl -sSL ... | bash -s -- [OPTIONS]

Options:
    -v VERSION    Install specific version (e.g., v0.1.0)
    -d DIR        Installation directory (default: /usr/local/bin)
    -f            Force overwrite existing installation
    -s            Skip scanner dependency prompts
    -h            Show this help message

Examples:
    # Install latest version
    curl -sSL https://raw.githubusercontent.com/victoralfred/devsec/main/install.sh | bash

    # Install specific version
    curl -sSL ... | bash -s -- -v v1.0.0

    # Install to custom directory
    curl -sSL ... | bash -s -- -d ~/.local/bin

    # Force reinstall without prompts
    curl -sSL ... | bash -s -- -f -s

EOF
    exit 0
}

# Detect operating system
detect_os() {
    local os
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        linux*)  echo "linux" ;;
        darwin*) echo "darwin" ;;
        *)       error "Unsupported operating system: $os"; exit 1 ;;
    esac
}

# Detect architecture
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)              error "Unsupported architecture: $arch"; exit 1 ;;
    esac
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check required dependencies
check_dependencies() {
    header "Checking Dependencies"

    local missing=()

    if ! command_exists curl && ! command_exists wget; then
        missing+=("curl or wget")
    fi

    if ! command_exists tar; then
        missing+=("tar")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing required dependencies: ${missing[*]}"
        error "Please install them and try again."
        exit 1
    fi

    success "All required dependencies found"
}

# Get latest version from GitHub
get_latest_version() {
    local latest
    if command_exists curl; then
        latest=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        latest=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    fi

    if [ -z "$latest" ]; then
        error "Failed to fetch latest version from GitHub"
        error "Please check your internet connection or specify a version with -v"
        exit 1
    fi

    echo "$latest"
}

# Download file
download_file() {
    local url="$1"
    local output="$2"

    if command_exists curl; then
        curl -fsSL "$url" -o "$output"
    else
        wget -q "$url" -O "$output"
    fi
}

# Verify checksum
verify_checksum() {
    local file="$1"
    local expected="$2"

    local actual
    if command_exists sha256sum; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command_exists shasum; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        warn "No sha256 tool found, skipping checksum verification"
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        error "Checksum verification failed!"
        error "Expected: $expected"
        error "Actual:   $actual"
        return 1
    fi

    return 0
}

# Download and install binary
install_binary() {
    local version="$1"
    local os="$2"
    local arch="$3"
    local install_dir="$4"

    header "Installing DevSec ${version}"

    local archive_name="${BINARY_NAME}_${version#v}_${os}_${arch}.tar.gz"
    local download_url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"
    local checksum_url="https://github.com/${REPO}/releases/download/${version}/checksums.txt"

    local tmp_dir
    tmp_dir=$(mktemp -d)
    # Store tmp_dir path for cleanup trap
    CLEANUP_DIR="$tmp_dir"
    trap '[ -n "$CLEANUP_DIR" ] && rm -rf "$CLEANUP_DIR"' EXIT

    info "Downloading ${archive_name}..."
    if ! download_file "$download_url" "${tmp_dir}/${archive_name}"; then
        error "Failed to download ${archive_name}"
        error "URL: ${download_url}"
        exit 1
    fi
    success "Downloaded ${archive_name}"

    # Download and verify checksum
    info "Verifying checksum..."
    if download_file "$checksum_url" "${tmp_dir}/checksums.txt"; then
        local expected_checksum
        expected_checksum=$(grep "${archive_name}" "${tmp_dir}/checksums.txt" | awk '{print $1}')
        if [ -n "$expected_checksum" ]; then
            if ! verify_checksum "${tmp_dir}/${archive_name}" "$expected_checksum"; then
                exit 1
            fi
            success "Checksum verified"
        else
            warn "Checksum not found in checksums.txt, skipping verification"
        fi
    else
        warn "Could not download checksums.txt, skipping verification"
    fi

    # Extract archive
    info "Extracting archive..."
    tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}"
    success "Extracted archive"

    # Check if binary exists in extracted files
    if [ ! -f "${tmp_dir}/${BINARY_NAME}" ]; then
        error "Binary not found in archive"
        exit 1
    fi

    # Install binary
    info "Installing to ${install_dir}..."

    # Create install directory if needed
    if [ ! -d "$install_dir" ]; then
        if [ -w "$(dirname "$install_dir")" ]; then
            mkdir -p "$install_dir"
        else
            sudo mkdir -p "$install_dir"
        fi
    fi

    # Copy binary
    if [ -w "$install_dir" ]; then
        cp "${tmp_dir}/${BINARY_NAME}" "${install_dir}/${BINARY_NAME}"
        chmod +x "${install_dir}/${BINARY_NAME}"
    else
        sudo cp "${tmp_dir}/${BINARY_NAME}" "${install_dir}/${BINARY_NAME}"
        sudo chmod +x "${install_dir}/${BINARY_NAME}"
    fi

    success "Installed ${BINARY_NAME} to ${install_dir}"

    # Verify installation
    if "${install_dir}/${BINARY_NAME}" version >/dev/null 2>&1; then
        success "Installation verified"
    else
        warn "Could not verify installation"
    fi
}

# Check if scanner is installed
check_scanner() {
    local name="$1"
    command_exists "$name"
}

# Prompt for scanner installation
prompt_scanner_install() {
    if [ "$SKIP_SCANNERS" = true ]; then
        return
    fi

    header "Optional Scanner Dependencies"
    info "DevSec can integrate with the following security scanners:"
    echo ""

    local os
    os=$(detect_os)

    # Check gitleaks
    if ! check_scanner "gitleaks"; then
        printf "${YELLOW}gitleaks${NC} - Secret detection (not installed)\n"
        if [ -t 0 ]; then
            read -p "  Install gitleaks? [y/N] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                install_gitleaks "$os"
            fi
        else
            info "  Run manually: brew install gitleaks (macOS) or download from GitHub"
        fi
    else
        printf "${GREEN}gitleaks${NC} - Secret detection (installed)\n"
    fi

    # Check semgrep
    if ! check_scanner "semgrep"; then
        printf "${YELLOW}semgrep${NC} - SAST scanning (not installed)\n"
        if [ -t 0 ]; then
            read -p "  Install semgrep? [y/N] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                install_semgrep
            fi
        else
            info "  Run manually: pip3 install semgrep or brew install semgrep"
        fi
    else
        printf "${GREEN}semgrep${NC} - SAST scanning (installed)\n"
    fi

    # Check trivy
    if ! check_scanner "trivy"; then
        printf "${YELLOW}trivy${NC} - Vulnerability scanning (not installed)\n"
        if [ -t 0 ]; then
            read -p "  Install trivy? [y/N] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                install_trivy "$os"
            fi
        else
            info "  Run manually: brew install trivy (macOS) or download from GitHub"
        fi
    else
        printf "${GREEN}trivy${NC} - Vulnerability scanning (installed)\n"
    fi

    echo ""
}

# Install gitleaks
install_gitleaks() {
    local os="$1"
    info "Installing gitleaks..."

    if [ "$os" = "darwin" ] && command_exists brew; then
        brew install gitleaks
    else
        # Download from GitHub releases
        local arch
        arch=$(detect_arch)
        local gitleaks_version
        gitleaks_version=$(curl -fsSL "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')

        local gitleaks_url="https://github.com/gitleaks/gitleaks/releases/download/v${gitleaks_version}/gitleaks_${gitleaks_version}_${os}_${arch}.tar.gz"
        local tmp_dir
        tmp_dir=$(mktemp -d)

        download_file "$gitleaks_url" "${tmp_dir}/gitleaks.tar.gz"
        tar -xzf "${tmp_dir}/gitleaks.tar.gz" -C "${tmp_dir}"

        if [ -w "/usr/local/bin" ]; then
            cp "${tmp_dir}/gitleaks" "/usr/local/bin/"
        else
            sudo cp "${tmp_dir}/gitleaks" "/usr/local/bin/"
        fi

        rm -rf "${tmp_dir}"
    fi

    if check_scanner "gitleaks"; then
        success "gitleaks installed"
    else
        warn "gitleaks installation may have failed"
    fi
}

# Install semgrep
install_semgrep() {
    info "Installing semgrep..."

    if command_exists brew; then
        brew install semgrep
    elif command_exists pip3; then
        pip3 install semgrep
    elif command_exists pip; then
        pip install semgrep
    else
        warn "Could not install semgrep. Please install pip3 first."
        return 1
    fi

    if check_scanner "semgrep"; then
        success "semgrep installed"
    else
        warn "semgrep installation may have failed"
    fi
}

# Install trivy
install_trivy() {
    local os="$1"
    info "Installing trivy..."

    if [ "$os" = "darwin" ] && command_exists brew; then
        brew install trivy
    else
        # Download from GitHub releases
        local arch
        arch=$(detect_arch)

        # Map architecture names for trivy
        local trivy_arch="$arch"
        [ "$arch" = "amd64" ] && trivy_arch="64bit"
        [ "$arch" = "arm64" ] && trivy_arch="ARM64"

        local trivy_os
        [ "$os" = "linux" ] && trivy_os="Linux"
        [ "$os" = "darwin" ] && trivy_os="macOS"

        local trivy_version
        trivy_version=$(curl -fsSL "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')

        local trivy_url="https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}/trivy_${trivy_version}_${trivy_os}-${trivy_arch}.tar.gz"
        local tmp_dir
        tmp_dir=$(mktemp -d)

        download_file "$trivy_url" "${tmp_dir}/trivy.tar.gz"
        tar -xzf "${tmp_dir}/trivy.tar.gz" -C "${tmp_dir}"

        if [ -w "/usr/local/bin" ]; then
            cp "${tmp_dir}/trivy" "/usr/local/bin/"
        else
            sudo cp "${tmp_dir}/trivy" "/usr/local/bin/"
        fi

        rm -rf "${tmp_dir}"
    fi

    if check_scanner "trivy"; then
        success "trivy installed"
    else
        warn "trivy installation may have failed"
    fi
}

# Check for existing installation
check_existing() {
    local install_dir="$1"

    if [ -f "${install_dir}/${BINARY_NAME}" ]; then
        if [ "$FORCE" = true ]; then
            warn "Overwriting existing installation"
            return 0
        fi

        local current_version
        current_version=$("${install_dir}/${BINARY_NAME}" version 2>/dev/null || echo "unknown")
        warn "DevSec is already installed at ${install_dir}/${BINARY_NAME}"
        info "Current version: ${current_version}"

        if [ -t 0 ]; then
            read -p "Overwrite? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Installation cancelled"
                exit 0
            fi
        else
            info "Use -f flag to force overwrite"
            exit 0
        fi
    fi
}

# Main function
main() {
    # Parse arguments
    while getopts ":v:d:fsh" opt; do
        case $opt in
            v) VERSION="$OPTARG" ;;
            d) INSTALL_DIR="$OPTARG" ;;
            f) FORCE=true ;;
            s) SKIP_SCANNERS=true ;;
            h) show_help ;;
            \?) error "Invalid option: -$OPTARG"; exit 1 ;;
            :) error "Option -$OPTARG requires an argument"; exit 1 ;;
        esac
    done

    # Set defaults
    INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

    # Print header
    printf "\n${BOLD}${CYAN}"
    cat << 'EOF'
    ____              ____
   / __ \___ _   __  / __/___  _____
  / / / / _ \ | / / _\ \/ _ \/ ___/
 / /_/ /  __/ |/ / ___/ /  __/ /__
/_____/\___/|___/ /____/\___/\___/

EOF
    printf "${NC}"
    printf "Installation Script v${INSTALL_SCRIPT_VERSION}\n\n"

    # Check dependencies
    check_dependencies

    # Detect platform
    header "Detecting Platform"
    local os arch
    os=$(detect_os)
    arch=$(detect_arch)
    success "Platform: ${os}/${arch}"

    # Get version
    header "Resolving Version"
    if [ -z "$VERSION" ]; then
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
    fi
    success "Version: ${VERSION}"

    # Check existing installation
    check_existing "$INSTALL_DIR"

    # Install binary
    install_binary "$VERSION" "$os" "$arch" "$INSTALL_DIR"

    # Prompt for scanner installation
    prompt_scanner_install

    # Final message
    header "Installation Complete"
    success "DevSec ${VERSION} has been installed to ${INSTALL_DIR}/${BINARY_NAME}"
    echo ""
    info "Get started:"
    echo "  ${INSTALL_DIR}/${BINARY_NAME} --help"
    echo "  ${INSTALL_DIR}/${BINARY_NAME} scan secrets ."
    echo "  ${INSTALL_DIR}/${BINARY_NAME} scan sast ."
    echo ""

    # Check if install dir is in PATH
    if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
        warn "${INSTALL_DIR} is not in your PATH"
        info "Add it to your shell profile:"
        echo "  export PATH=\"\$PATH:${INSTALL_DIR}\""
        echo ""
    fi
}

main "$@"
