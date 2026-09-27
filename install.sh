#!/usr/bin/env bash
# Install the LocalVault CLI (`lv`) from the latest GitHub Release.
# Usage: curl -fsSL https://raw.githubusercontent.com/zaain-ali/local-vault/main/install.sh | bash
set -euo pipefail

REPO="zaain-ali/local-vault"
RELEASE_BASE="https://github.com/${REPO}/releases/latest/download"

# Brand colors (apps/cli/internal/ui/theme.go)
GOLD_RGB="229;181;103"   # #e5b567
MUTED_RGB="140;140;140"  # #8c8c8c
GREEN_RGB="123;200;148"  # #7bc894

color_enabled() {
  if [[ -n "${NO_COLOR:-}" ]]; then
    return 1
  fi
  if [[ "${TERM:-}" == "dumb" ]]; then
    return 1
  fi
  [[ -t 1 ]]
}

# When piped (curl | bash), stdout is not a TTY — still color if stderr is a TTY.
color_enabled_out() {
  if [[ -n "${NO_COLOR:-}" ]]; then
    return 1
  fi
  if [[ "${TERM:-}" == "dumb" ]]; then
    return 1
  fi
  [[ -t 1 ]] || [[ -t 2 ]]
}

fg() {
  local rgb="$1"
  shift
  if color_enabled_out; then
    printf '\033[38;2;%sm%s\033[0m' "$rgb" "$*"
  else
    printf '%s' "$*"
  fi
}

print_banner() {
  local install_path="$1"
  local wordmark
  wordmark="$(cat <<'EOF'
  ██╗      ██████╗  ██████╗ █████╗ ██╗
  ██║     ██╔═══██╗██╔════╝██╔══██╗██║
  ██║     ██║   ██║██║     ███████║██║
  ██║     ██║   ██║██║     ██╔══██║██║
  ███████╗╚██████╔╝╚██████╗██║  ██║███████╗
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝
   ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
   ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
   ██║   ██║███████║██║   ██║██║     ██║
   ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║
    ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║
     ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
EOF
)"

  printf '\n'
  while IFS= read -r line; do
    printf '%s\n' "$(fg "$GOLD_RGB" "$line")"
  done <<<"$wordmark"
  printf '\n'
  printf '  %s\n' "$(fg "$MUTED_RGB" "Encrypted secrets for dev teams. No cloud. No leaks.")"
  printf '\n'
  printf '  %s  %s\n' "$(fg "$GREEN_RGB" "✓")" "Installed lv to ${install_path}"
  printf '     %s  %s\n' "$(fg "$MUTED_RGB" "Next:")" "$(fg "$GOLD_RGB" "lv login")"
  printf '\n'
}

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$os" in
    linux) os="linux" ;;
    darwin) os="darwin" ;;
    *)
      echo "error: unsupported OS '$os' (supported: linux, darwin)" >&2
      exit 1
      ;;
  esac

  case "$arch" in
    x86_64 | amd64) arch="amd64" ;;
    aarch64 | arm64) arch="arm64" ;;
    *)
      echo "error: unsupported architecture '$arch' (supported: amd64, arm64)" >&2
      exit 1
      ;;
  esac

  echo "${os}_${arch}"
}

resolve_bin_dir() {
  if [[ -n "${BIN_DIR:-}" ]]; then
    mkdir -p "$BIN_DIR"
    echo "$BIN_DIR"
    return
  fi

  if [[ -d /usr/local/bin ]]; then
    if [[ -w /usr/local/bin ]]; then
      echo /usr/local/bin
      return
    fi
    if command -v sudo >/dev/null 2>&1; then
      echo /usr/local/bin
      return
    fi
  fi

  local local_bin="${HOME}/.local/bin"
  mkdir -p "$local_bin"
  echo "$local_bin"
}

needs_sudo() {
  local dir="$1"
  [[ "$dir" == /usr/local/bin ]] && [[ ! -w /usr/local/bin ]]
}

download() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    echo "error: need curl or wget to download lv" >&2
    exit 1
  fi
}

main() {
  local platform archive url tmpdir bin_dir
  platform="$(detect_platform)"
  archive="lv_${platform}.tar.gz"
  url="${RELEASE_BASE}/${archive}"
  bin_dir="$(resolve_bin_dir)"

  tmpdir="$(mktemp -d)"
  # Expand path now — trap runs after main's locals are gone under set -u.
  # shellcheck disable=SC2064
  trap "rm -rf '${tmpdir}'" EXIT

  echo "Downloading ${archive}..."
  download "$url" "${tmpdir}/${archive}"

  tar -xzf "${tmpdir}/${archive}" -C "$tmpdir" lv

  if needs_sudo "$bin_dir"; then
    echo "Installing to ${bin_dir} (sudo)..."
    sudo mv "${tmpdir}/lv" "${bin_dir}/lv"
    sudo chmod 755 "${bin_dir}/lv"
  else
    echo "Installing to ${bin_dir}..."
    mv "${tmpdir}/lv" "${bin_dir}/lv"
    chmod 755 "${bin_dir}/lv"
  fi

  if ! command -v lv >/dev/null 2>&1; then
    if [[ ":${PATH}:" != *":${bin_dir}:"* ]]; then
      echo "warning: ${bin_dir} is not on your PATH. Add it, e.g.:" >&2
      echo "  export PATH=\"${bin_dir}:\$PATH\"" >&2
    fi
  fi

  print_banner "${bin_dir}/lv"
}

main "$@"
