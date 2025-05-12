#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Configuration
readonly REPO='AssetsArt/easy-proxy' # Replace with your GitHub username/repo
readonly BINARY='easy-proxy'
readonly INSTALL_DIR='/usr/local/bin'
readonly CONFIG_DIR='/etc/easy-proxy'
readonly SERVICE_FILE='/etc/systemd/system/easy-proxy.service'

CREATE_SERVICE=true

# Log and error helpers
log() { printf '%s\n' "$*"; }
err() { printf 'Error: %s\n' "$*" >&2; exit 1; }

# Parse args
[[ "${1:-}" == '--no-service' ]] && CREATE_SERVICE=false

# Detect OS, arch, and libc
detect_system() {
  local os arch ldout
  os=$(uname | tr '[:upper:]' '[:lower:]')
  [[ $os == linux ]] || err 'Only Linux is supported.'
  arch=$(uname -m)
  case $arch in
    x86_64) ;;
    arm64|aarch64) arch=aarch64 ;;
    *) err "Unsupported arch: $arch" ;;
  esac
  ldout=$(ldd --version 2>&1)
  OS_TYPE=$([[ $ldout == *musl* ]] && echo musl || echo gnu)
  OS=$os; ARCH=$arch
}

# Fetch latest GitHub release tag
fetch_latest_tag() {
  local tag
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -Po '"tag_name":\s*"\K[^"]+')
  [[ $tag ]] || err 'Failed to fetch latest tag'
  echo "$tag"
}

# Download binary + checksums, verify and install
download_and_install() {
  local tag=$1 name sum tmpsums
  name="$BINARY-$ARCH-$OS-$OS_TYPE"
  DOWNLOAD_URL="https://github.com/$REPO/releases/download/$tag/$name"
  tmpsums=$(mktemp)
  trap 'rm -f "$tmpsums"' EXIT

  curl -fsSL "$DOWNLOAD_URL" -o "$name" \
    || err "Download failed: $name"
  curl -fsSL "https://github.com/$REPO/releases/download/$tag/linux-checksums.txt" \
    > "$tmpsums" \
    || err 'Failed to fetch checksums'

  sum=$(grep -F "$name" "$tmpsums" | awk '{print $1}')
  [[ $sum ]] || err 'Checksum entry missing'
  echo "$sum  $name" | sha256sum --check --quiet \
    || err 'Checksum mismatch'

  chmod +x "$name"
  sudo mv "$name" "$INSTALL_DIR/$BINARY"
}

# Create default config if missing
setup_config() {
  sudo mkdir -p "$CONFIG_DIR"/{proxy,tls,scripts}
  local conf="$CONFIG_DIR/conf.yaml"
  if [[ ! -f $conf ]]; then
    log 'Generating default config…'
    sudo tee "$conf" > /dev/null <<EOF
proxy:
  http: "0.0.0.0:80"
  https: "0.0.0.0:443"
config_dir: "$CONFIG_DIR/proxy"
acme_store: "$CONFIG_DIR/acme.json"
pingora:
  daemon: true
  threads: $(nproc)
  grace_period_seconds: 60
  graceful_shutdown_timeout_seconds: 10
EOF
  fi
}

# Create start/stop/restart scripts
setup_scripts() {
  log 'Creating control scripts…'
  local s=$CONFIG_DIR/scripts
  sudo tee "$s/start.sh" > /dev/null <<EOF
#!/usr/bin/env bash
mkdir -p /var/log/$BINARY
exec $INSTALL_DIR/$BINARY >> /var/log/$BINARY/$BINARY.log 2>&1
EOF

  sudo tee "$s/stop.sh" > /dev/null <<EOF
#!/usr/bin/env bash
pkill -f "$INSTALL_DIR/$BINARY" || echo 'Not running'
EOF

  sudo tee "$s/restart.sh" > /dev/null <<EOF
#!/usr/bin/env bash
$s/stop.sh && $s/start.sh
EOF

  sudo chmod +x "$s"/*.sh
}

# Create or reload systemd service
setup_service() {
  [[ $CREATE_SERVICE == true ]] || return
  if [[ ! -f $SERVICE_FILE ]]; then
    log 'Installing systemd service…'
    sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Easy Proxy Service
After=network.target
[Service]
Type=simple
ExecStart=$CONFIG_DIR/scripts/start.sh
ExecStop=$CONFIG_DIR/scripts/stop.sh
ExecReload=$INSTALL_DIR/$BINARY -r
Restart=on-failure
RestartSec=5
KillMode=process
[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now easy-proxy
  else
    log 'Reloading existing service…'
    if $INSTALL_DIR/$BINARY -t; then
      sudo systemctl restart easy-proxy
    else
      err 'Invalid configuration'
    fi
  fi
  log 'Setup complete.'
}

main() {
  detect_system
  local tag
  tag=$(fetch_latest_tag)
  download_and_install "$tag"
  setup_config
  setup_scripts
  setup_service
}

# Call main function
main "$@"