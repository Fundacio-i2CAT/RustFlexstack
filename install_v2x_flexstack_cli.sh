#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)
#
# install_v2x_flexstack_cli.sh — Universal installer for V2X FlexStack CLI (v2x_cli & v2x_cli_cv2x)
#
# Supported platforms:
#   - Cohda MK6 ag550 (Firmware 20) -> C-V2X (PC5 Mode 4) & Raw Link Layer
#   - Cohda MK6 ag550 (Firmware 19) -> C-V2X (PC5 Mode 4) & Raw Link Layer
#   - Cohda MK6C / ag15 (MDM9150)   -> C-V2X (PC5 Mode 4) & Raw Link Layer
#   - Generic Linux (x86_64, aarch64) -> ETSI TS 103 097 / 102 941 Raw Link Layer
#
# Usage (rustup-style):
#   # Using curl:
#   curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/Fundacio-i2CAT/RustFlexstack/master/install_v2x_flexstack_cli.sh | sh
#
#   # Using wget (pre-installed on Cohda MK6 devices):
#   wget -qO- https://raw.githubusercontent.com/Fundacio-i2CAT/RustFlexstack/master/install_v2x_flexstack_cli.sh | sh
#
#   # From a local lab mirror / offline server:
#   wget -qO- http://192.168.59.56:8000/install_v2x_flexstack_cli.sh | sh -s -- http://192.168.59.56:8000

set -e

REPO="Fundacio-i2CAT/RustFlexstack"
DEFAULT_TAG="v0.3.6"
TAG="${V2X_TAG:-$DEFAULT_TAG}"
MIRROR="${V2X_MIRROR:-}"
DEST_DIR="/usr/local/bin"
CV2X_FLAVOUR="${V2X_CV2X_FLAVOUR:-}"

# Parse CLI arguments if passed via "sh -s -- [args]"
while [ $# -gt 0 ]; do
    case "$1" in
        http://*|https://*)
            MIRROR="$1"
            shift
            ;;
        --mirror|-m)
            MIRROR="$2"
            shift 2
            ;;
        --tag|-t)
            TAG="$2"
            shift 2
            ;;
        --dest|-d)
            DEST_DIR="$2"
            shift 2
            ;;
        --flavour|--flavor|-f|--cv2x-flavour)
            CV2X_FLAVOUR="$2"
            shift 2
            ;;
        --help|-h)
            echo "Universal V2X FlexStack CLI Installer"
            echo "Usage: $0 [OPTIONS] [MIRROR_URL]"
            echo ""
            echo "Options:"
            echo "  --mirror, -m <URL>       Custom download mirror (e.g. http://192.168.59.56:8000)"
            echo "  --tag, -t <TAG>          GitHub release tag [default: $DEFAULT_TAG]"
            echo "  --dest, -d <DIR>         Installation directory [default: /usr/local/bin]"
            echo "  --cv2x-flavour, -f <FLV> Force C-V2X flavour (mk6-fw20, mk6-fw19, mk6c)"
            echo "  --help, -h               Show this help"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

echo "============================================================"
echo "    i2CAT V2X FlexStack® CLI Installer"
echo "============================================================"

# 1. Detect Architecture and OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux) ;;
    Darwin)
        echo "Note: macOS detected. Only user-space / PKI simulation tools are supported."
        ;;
    *)
        echo "ERROR: Unsupported OS '$OS'. Supported: Linux, macOS."
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        NORM_ARCH="x86_64"
        ;;
    aarch64|arm64)
        NORM_ARCH="aarch64"
        ;;
    *)
        echo "ERROR: Unsupported CPU architecture '$ARCH'."
        echo "Supported architectures: x86_64, aarch64."
        exit 1
        ;;
esac

echo "[*] Host Architecture : $NORM_ARCH ($OS)"

# 2. Detect C-V2X hardware / firmware flavour on AArch64
HAS_CV2X=0

has_symbol() {
    _sym="$1"
    _file="$2"
    grep -a -q "$_sym" "$_file" 2>/dev/null || grep -q "$_sym" "$_file" 2>/dev/null || (command -v strings >/dev/null 2>&1 && strings "$_file" 2>/dev/null | grep -q "$_sym")
}

TELUX_LIB=""
if [ "$NORM_ARCH" = "aarch64" ]; then
    for _p in /usr/lib/libtelux_cv2x.so* /usr/lib64/libtelux_cv2x.so* /lib/libtelux_cv2x.so* /usr/local/lib/libtelux_cv2x.so* /usr/lib/aarch64-linux-gnu/libtelux_cv2x.so*; do
        if [ -e "$_p" ]; then
            TELUX_LIB="$_p"
            break
        fi
    done
fi

if [ -n "$CV2X_FLAVOUR" ]; then
    HAS_CV2X=1
    echo "[*] Hardware Mode     : Forced C-V2X Flavour -> $CV2X_FLAVOUR"
elif [ -n "$TELUX_LIB" ]; then
    HAS_CV2X=1
    echo "[*] Hardware Detected : Qualcomm Telematics C-V2X Radio Subsystem ($TELUX_LIB)"

    if has_symbol "Cv2xFactoryImpl" "$TELUX_LIB"; then
        CV2X_FLAVOUR="mk6-fw20"
        echo "    Firmware Flavour  : Cohda MK6 ag550 (Quectel AG550 / SA515M) — Firmware 20"
    elif has_symbol "Cv2xRadio" "$TELUX_LIB" && ! has_symbol "DsiCv2xRadio" "$TELUX_LIB"; then
        CV2X_FLAVOUR="mk6c"
        echo "    Firmware Flavour  : Cohda MK6C / MK6 ag15 (Qualcomm MDM9150) — Snaptel"
    else
        CV2X_FLAVOUR="mk6-fw19"
        echo "    Firmware Flavour  : Cohda MK6 ag550 (Quectel AG550 / SA515M) — Firmware 19"
    fi
else
    echo "[*] Environment       : Standard Linux node (Raw Ethernet / ITS-G5 link layer)"
fi

# 3. Determine Target Binary & Download URLs
if [ "$HAS_CV2X" = "1" ]; then
    V2X_CLI_FLAVOUR="cohda"
elif [ "$NORM_ARCH" = "aarch64" ]; then
    V2X_CLI_FLAVOUR="aarch64"
else
    V2X_CLI_FLAVOUR="x86"
fi

echo "[*] Target Binary     : v2x_cli_${V2X_CLI_FLAVOUR}"

if [ -n "$MIRROR" ]; then
    BASE_URL="${MIRROR%/}"
    echo "[*] Download Source   : Local Mirror ($BASE_URL)"
else
    BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
    echo "[*] Download Source   : GitHub Release ${TAG} (${REPO})"
fi

PRIMARY_CLI_URL="${BASE_URL}/v2x_cli_${V2X_CLI_FLAVOUR}"
FALLBACK_CLI_URL="${BASE_URL}/v2x_cli"
TAR_URL="${BASE_URL}/rustflexstack-${TAG}-${NORM_ARCH}-linux.tar.gz"
CV2X_BIN_URL="${BASE_URL}/v2x_cli_cv2x-${CV2X_FLAVOUR}"

# 4. Prepare Download Helper
download_file() {
    _url="$1"
    _out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -f -sSL "$_url" -o "$_out"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$_out" "$_url"
    else
        echo "ERROR: Neither 'curl' nor 'wget' was found on this system."
        exit 1
    fi
}

TMP_DIR="/tmp/v2x_flexstack_install_$$"
mkdir -p "$TMP_DIR"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# 5. Download Binaries
echo ""
echo "[*] Downloading components..."

# A. Standard v2x_cli binary (GeoNetworking / IEEE 802.11p / Raw Socket)
GOT_V2X_CLI=0
echo "    Fetching v2x_cli_${V2X_CLI_FLAVOUR} ..."
if download_file "$PRIMARY_CLI_URL" "$TMP_DIR/v2x_cli" 2>/dev/null && [ -s "$TMP_DIR/v2x_cli" ]; then
    chmod +x "$TMP_DIR/v2x_cli"
    GOT_V2X_CLI=1
elif download_file "$FALLBACK_CLI_URL" "$TMP_DIR/v2x_cli" 2>/dev/null && [ -s "$TMP_DIR/v2x_cli" ]; then
    chmod +x "$TMP_DIR/v2x_cli"
    GOT_V2X_CLI=1
fi

if [ "$GOT_V2X_CLI" = "0" ]; then
    echo "    Trying tarball rustflexstack-${TAG}-${NORM_ARCH}-linux.tar.gz ..."
    if download_file "$TAR_URL" "$TMP_DIR/archive.tar.gz" 2>/dev/null && [ -s "$TMP_DIR/archive.tar.gz" ]; then
        tar -xzf "$TMP_DIR/archive.tar.gz" -C "$TMP_DIR"
        FOUND_CLI="$(find "$TMP_DIR" -type f -name "v2x_cli*" | head -n 1)"
        if [ -n "$FOUND_CLI" ]; then
            mv -f "$FOUND_CLI" "$TMP_DIR/v2x_cli"
            chmod +x "$TMP_DIR/v2x_cli"
            GOT_V2X_CLI=1
        fi
    fi
fi

if [ "$GOT_V2X_CLI" = "1" ]; then
    echo "    [+] v2x_cli (from v2x_cli_${V2X_CLI_FLAVOUR}) downloaded successfully."
else
    echo "    [!] Notice: could not fetch v2x_cli_${V2X_CLI_FLAVOUR} from $PRIMARY_CLI_URL"
fi

# B. Qualcomm C-V2X direct radio binary (if device has C-V2X hardware)
GOT_CV2X_CLI=0
if [ "$HAS_CV2X" = "1" ]; then
    echo "    Fetching v2x_cli_cv2x (${CV2X_FLAVOUR}) ..."
    if download_file "$CV2X_BIN_URL" "$TMP_DIR/v2x_cli_cv2x" 2>/dev/null && [ -s "$TMP_DIR/v2x_cli_cv2x" ]; then
        chmod +x "$TMP_DIR/v2x_cli_cv2x"
        GOT_CV2X_CLI=1
        echo "    [+] v2x_cli_cv2x (${CV2X_FLAVOUR}) downloaded successfully."
    elif download_file "${BASE_URL}/v2x_cli_cv2x" "$TMP_DIR/v2x_cli_cv2x" 2>/dev/null && [ -s "$TMP_DIR/v2x_cli_cv2x" ]; then
        chmod +x "$TMP_DIR/v2x_cli_cv2x"
        GOT_CV2X_CLI=1
        echo "    [+] v2x_cli_cv2x (generic) downloaded successfully."
    else
        echo "    [!] Warning: could not download C-V2X binary from $CV2X_BIN_URL"
    fi
fi

# 6. Install to destination
echo ""
echo "[*] Installing binaries to ${DEST_DIR}..."

install_bin() {
    _src="$1"
    _target="$2"

    mkdir -p "$DEST_DIR" 2>/dev/null || true

    if [ -w "$DEST_DIR" ] || [ "$(id -u)" = "0" ]; then
        cp -f "$_src" "$_target"
        chmod +x "$_target"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo mkdir -p "$DEST_DIR"
        sudo cp -f "$_src" "$_target"
        sudo chmod +x "$_target"
    elif [ -t 0 ] && command -v sudo >/dev/null 2>&1; then
        echo "    [sudo required to write into ${DEST_DIR}]"
        sudo mkdir -p "$DEST_DIR"
        sudo cp -f "$_src" "$_target"
        sudo chmod +x "$_target"
    else
        # Fallback to ~/.local/bin
        USER_DEST="$HOME/.local/bin"
        mkdir -p "$USER_DEST"
        _user_target="$USER_DEST/$(basename "$_target")"
        cp -f "$_src" "$_user_target"
        chmod +x "$_user_target"
        echo "    [!] Notice: Installed to $_user_target (add to PATH if needed)."
        return
    fi
}

if [ "$GOT_V2X_CLI" = "1" ]; then
    install_bin "$TMP_DIR/v2x_cli" "${DEST_DIR}/v2x_cli"
fi

if [ "$GOT_CV2X_CLI" = "1" ]; then
    install_bin "$TMP_DIR/v2x_cli_cv2x" "${DEST_DIR}/v2x_cli_cv2x"
fi

# 7. Verification Test
echo ""
echo "[*] Verifying installation..."

VERIFY_SUCCESS=0

if [ "$GOT_CV2X_CLI" = "1" ] && [ -x "${DEST_DIR}/v2x_cli_cv2x" ]; then
    if "${DEST_DIR}/v2x_cli_cv2x" --help >/dev/null 2>&1; then
        echo "    [+] ${DEST_DIR}/v2x_cli_cv2x (C-V2X PC5 Mode 4) verified OK!"
        VERIFY_SUCCESS=1
    else
        echo "    [!] Warning: ${DEST_DIR}/v2x_cli_cv2x failed self-test."
    fi
fi

if [ "$GOT_V2X_CLI" = "1" ] && [ -x "${DEST_DIR}/v2x_cli" ]; then
    if "${DEST_DIR}/v2x_cli" --help >/dev/null 2>&1; then
        echo "    [+] ${DEST_DIR}/v2x_cli (Raw Ethernet / 802.11p) verified OK!"
        VERIFY_SUCCESS=1
    else
        echo "    [!] Warning: ${DEST_DIR}/v2x_cli failed self-test."
    fi
fi

echo ""
echo "============================================================"
if [ "$VERIFY_SUCCESS" = "1" ]; then
    echo " SUCCESS: V2X FlexStack® CLI installed successfully!"
    echo "============================================================"
    if [ "$GOT_CV2X_CLI" = "1" ]; then
        echo " Run C-V2X station : v2x_cli_cv2x --help"
    fi
    if [ "$GOT_V2X_CLI" = "1" ]; then
        echo " Run 802.11p / Raw : v2x_cli --help"
    fi
else
    echo " ERROR: Installation could not be verified."
    exit 1
fi

