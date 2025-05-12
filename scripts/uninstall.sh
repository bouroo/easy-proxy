#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

readonly BINARY="easy-proxy"
readonly INSTALL_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/easy-proxy"
readonly SERVICE_FILE="/etc/systemd/system/${BINARY}.service"

log()   { printf '[INFO] %s\n' "$*"; }
warn()  { printf '[WARN] %s\n' "$*" >&2; }
error() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

stop_disable_service() {
  log "Stopping and disabling ${BINARY} service…"
  sudo systemctl stop "${BINARY}.service" --quiet || warn "Service not running"
  sudo systemctl disable "${BINARY}.service" --quiet || warn "Service not enabled"
}

remove_binary() {
  local path="${INSTALL_DIR}/${BINARY}"
  if [[ -f $path ]]; then
    log "Removing binary at $path"
    sudo rm -f "$path"
  else
    warn "Binary not found at $path"
  fi
}

remove_config_dir() {
  if [[ -d $CONFIG_DIR ]]; then
    log "Removing config directory $CONFIG_DIR"
    sudo rm -rf "$CONFIG_DIR"
  else
    warn "Config directory not found at $CONFIG_DIR"
  fi
}

remove_service_file() {
  if [[ -f $SERVICE_FILE ]]; then
    log "Removing systemd unit $SERVICE_FILE"
    sudo rm -f "$SERVICE_FILE"
    log "Reloading systemd daemon"
    sudo systemctl daemon-reload --quiet
  else
    warn "Unit file not found at $SERVICE_FILE"
  fi
}

kill_orphan_processes() {
  if pgrep -f "/usr/local/bin/${BINARY}" >/dev/null; then
    log "Killing leftover ${BINARY} processes"
    sudo pkill -9 -f "/usr/local/bin/${BINARY}"
  fi
}

main() {
  stop_disable_service
  remove_binary
  remove_config_dir
  remove_service_file
  kill_orphan_processes
  log "${BINARY} uninstalled successfully."
}

# Call main function
main "$@"