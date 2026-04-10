#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="lankeqy007"
REPO_NAME="code-rg"

COMPONENT="dan-web"
INSTALL_DIR="$PWD/dan-runtime"
VERSION="latest"
CPA_BASE_URL=""
CPA_TOKEN=""
MAIL_API_URL=""
MAIL_API_KEY=""
THREADS="20"
WEB_TOKEN="linuxdo"
PORT="25666"
DOMAINS=""
ADMIN_EMAIL=""
ADMIN_PASS=""
EMAIL_DOMAIN=""
AUTO_START="1"
SYSTEMD="0"
SERVICE_NAME="dan-web"
BACKGROUND="0"
LOG_FILE=""
PID_FILE=""

usage() {
  cat <<'EOF'
Usage:
  install.sh [options]

Options:
  --component dan-web|dan
  --install-dir DIR
  --version latest|vX.Y.Z
  --cpa-base-url URL
  --cpa-token TOKEN
  --mail-api-url URL
  --mail-api-key KEY
  --threads N
  --web-token TOKEN
  --port N
  --domains CSV
  --admin-email EMAIL
  --admin-pass PASS
  --email-domain DOMAIN
  --no-auto-start
  --systemd
  --service-name NAME
  --background
  --log-file PATH
  --pid-file PATH
  -h, --help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --component) COMPONENT="${2:-}"; shift 2 ;;
    --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --cpa-base-url) CPA_BASE_URL="${2:-}"; shift 2 ;;
    --cpa-token) CPA_TOKEN="${2:-}"; shift 2 ;;
    --mail-api-url) MAIL_API_URL="${2:-}"; shift 2 ;;
    --mail-api-key) MAIL_API_KEY="${2:-}"; shift 2 ;;
    --threads) THREADS="${2:-}"; shift 2 ;;
    --web-token) WEB_TOKEN="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --domains) DOMAINS="${2:-}"; shift 2 ;;
    --admin-email) ADMIN_EMAIL="${2:-}"; shift 2 ;;
    --admin-pass) ADMIN_PASS="${2:-}"; shift 2 ;;
    --email-domain) EMAIL_DOMAIN="${2:-}"; shift 2 ;;
    --no-auto-start) AUTO_START="0"; shift ;;
    --systemd) SYSTEMD="1"; shift ;;
    --service-name) SERVICE_NAME="${2:-}"; shift 2 ;;
    --background) BACKGROUND="1"; shift ;;
    --log-file) LOG_FILE="${2:-}"; shift 2 ;;
    --pid-file) PID_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }
}

json_escape() {
  local value="${1-}"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

detect_os() {
  case "$(uname -s)" in
    Linux) printf 'linux' ;;
    Darwin) printf 'darwin' ;;
    MINGW*|MSYS*|CYGWIN*) printf 'windows' ;;
    *) echo "Unsupported operating system: $(uname -s)" >&2; exit 1 ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    arm64|aarch64) printf 'arm64' ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
}

build_release_base() {
  if [[ "$VERSION" == "latest" ]]; then
    printf 'https://github.com/%s/%s/releases/latest/download' "$REPO_OWNER" "$REPO_NAME"
  else
    printf 'https://github.com/%s/%s/releases/download/%s' "$REPO_OWNER" "$REPO_NAME" "$VERSION"
  fi
}

require_cmd curl

OS="$(detect_os)"
ARCH="$(detect_arch)"

case "$COMPONENT" in
  dan|dan-web) ;;
  *) echo "Unsupported component: $COMPONENT" >&2; exit 1 ;;
esac

mkdir -p "$INSTALL_DIR/config"
RELEASE_BASE="$(build_release_base)"
CHECKSUM_URL="${RELEASE_BASE}/SHA256SUMS.txt"
TMP_DIR="$INSTALL_DIR/.download.$$"
mkdir -p "$TMP_DIR"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

download_asset() {
  local asset_name="$1"
  local output_name="$2"
  local download_url="${RELEASE_BASE}/${asset_name}"
  local tmp_file="$TMP_DIR/${output_name}"

  echo "Downloading ${asset_name}..."
  curl -fL "$download_url" -o "$tmp_file"
  chmod +x "$tmp_file"
  mv -f "$tmp_file" "$INSTALL_DIR/$output_name"
}

echo "Downloading SHA256SUMS.txt..."
curl -fL "$CHECKSUM_URL" -o "$TMP_DIR/SHA256SUMS.txt"
tr -d '\r' < "$TMP_DIR/SHA256SUMS.txt" > "$TMP_DIR/SHA256SUMS.unix.txt"

verify_asset() {
  local asset_name="$1"
  local file_path="$2"
  local expected
  expected="$(awk -v name="$asset_name" '$2 == name { print $1; exit }' "$TMP_DIR/SHA256SUMS.unix.txt")"
  [[ -n "$expected" ]] || { echo "Missing checksum entry for ${asset_name}." >&2; exit 1; }

  local actual=""
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file_path" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file_path" | awk '{print $1}')"
  fi
  [[ -z "$actual" || "$expected" == "$actual" ]] || { echo "Checksum verification failed for ${asset_name}." >&2; exit 1; }
}

ASSET_NAME="${COMPONENT}-${OS}-${ARCH}"
download_asset "$ASSET_NAME" "$COMPONENT"
verify_asset "$ASSET_NAME" "$INSTALL_DIR/$COMPONENT"

if [[ "$COMPONENT" == "dan-web" ]]; then
  DAN_ASSET="dan-${OS}-${ARCH}"
  if grep -q "[[:space:]]${DAN_ASSET}\$" "$TMP_DIR/SHA256SUMS.unix.txt"; then
    download_asset "$DAN_ASSET" "dan"
    verify_asset "$DAN_ASSET" "$INSTALL_DIR/dan"
  fi
fi

cat > "$INSTALL_DIR/config.json" <<EOF
{
  "ak_file": "ak.txt",
  "rk_file": "rk.txt",
  "token_json_dir": "codex_tokens",
  "upload_api_url": "$(json_escape "${CPA_BASE_URL%/}")/v0/management/auth-files",
  "upload_api_token": "$(json_escape "$CPA_TOKEN")",
  "mail_api_url": "$(json_escape "$MAIL_API_URL")",
  "mail_api_key": "$(json_escape "$MAIL_API_KEY")",
  "admin_email": "$(json_escape "$ADMIN_EMAIL")",
  "admin_pass": "$(json_escape "$ADMIN_PASS")",
  "email_domain": "$(json_escape "$EMAIL_DOMAIN")",
  "oauth_issuer": "https://auth.openai.com",
  "oauth_client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
  "oauth_redirect_uri": "http://localhost:1455/auth/callback",
  "enable_oauth": true,
  "oauth_required": true
}
EOF

cat > "$INSTALL_DIR/config/web_config.json" <<EOF
{
  "manual_default_threads": ${THREADS},
  "web_token": "$(json_escape "$WEB_TOKEN")",
  "cpa_base_url": "$(json_escape "$CPA_BASE_URL")",
  "cpa_token": "$(json_escape "$CPA_TOKEN")",
  "mail_api_url": "$(json_escape "$MAIL_API_URL")",
  "mail_api_key": "$(json_escape "$MAIL_API_KEY")",
  "domains": [$(DOMAINS="$DOMAINS" python3 - <<'PY'
import json, os
parts=[p.strip() for p in os.environ.get("DOMAINS","").split(",") if p.strip()]
print(",".join(json.dumps(p) for p in parts))
PY
)],
  "admin_email": "$(json_escape "$ADMIN_EMAIL")",
  "admin_pass": "$(json_escape "$ADMIN_PASS")",
  "email_domain": "$(json_escape "$EMAIL_DOMAIN")",
  "auto_start": $([[ "$AUTO_START" == "1" ]] && printf 'true' || printf 'false'),
  "port": ${PORT}
}
EOF

if [[ "$SYSTEMD" == "1" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "--systemd requires root." >&2
    exit 1
  fi
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=${SERVICE_NAME}
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/${COMPONENT}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}.service"
fi

if [[ "$BACKGROUND" == "1" ]]; then
  LOG_FILE="${LOG_FILE:-$INSTALL_DIR/${COMPONENT}.log}"
  PID_FILE="${PID_FILE:-$INSTALL_DIR/${COMPONENT}.pid}"

  if [[ -f "$PID_FILE" ]]; then
    old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      kill "$old_pid" 2>/dev/null || true
      sleep 1
    fi
  fi

  (
    cd "$INSTALL_DIR"
    nohup "./${COMPONENT}" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
  )
fi

echo
echo "Installed to: $INSTALL_DIR"
echo "Binary: $INSTALL_DIR/$COMPONENT"
echo "Config: $INSTALL_DIR/config/web_config.json"
if [[ "$COMPONENT" == "dan-web" ]]; then
  echo "Status:"
  echo "  curl -s -H \"Authorization: Bearer ${WEB_TOKEN}\" http://127.0.0.1:${PORT}/api/status"
  echo "Start:"
  echo "  curl -s -X POST -H \"Authorization: Bearer ${WEB_TOKEN}\" http://127.0.0.1:${PORT}/api/start | jq"
  echo "Stop:"
  echo "  curl -s -X POST -H \"Authorization: Bearer ${WEB_TOKEN}\" http://127.0.0.1:${PORT}/api/stop | jq"
fi
