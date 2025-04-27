#!/usr/bin/env bash
###############################################################################
# debian_server.sh  –  v2.0  (27 Apr 2025)
#
# Harden a fresh Debian host and provision a key-based admin account.
#
# Usage: sudo ./debian_server.sh -u USER -k KEYFILE [OPTIONS]
#   -u USER    admin account to create / manage            (required)
#   -k FILE    path to public SSH key                      (required)
#   -p PORT    SSH port (default: 22)
#   -s         lock the account password  (default)
#   -P         generate & store a random sudo password
#   -n         dry-run – print but do not execute actions
#   -v         verbose – echo every command (set -x)
#   -h         help
###############################################################################

set -euo pipefail

###############################################################################
#  Colour-aware logging helpers
###############################################################################
if [[ -t 1 && ${NO_COLOR:-0} -eq 0 ]]; then
  BLUE='\e[34m'; YELLOW='\e[33m'; RED='\e[31m'; NC='\e[0m'
else
  BLUE=''; YELLOW=''; RED=''; NC=''
fi
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error() { echo -e "${RED}[FAIL]${NC}  $*" >&2; }

###############################################################################
#  Trap: keep original exit code
###############################################################################
trap 'rc=$?; [[ $rc -ne 0 ]] && error "cmd \"${BASH_COMMAND}\" failed (rc=$rc) at line $LINENO"; exit $rc' ERR

###############################################################################
#  Global log
###############################################################################
LOGFILE="/var/log/fresh_debian_server.log"
mkdir -p /var/log
exec  > >(tee -a "$LOGFILE") 2>&1

###############################################################################
#  CLI parsing
###############################################################################
ADMIN_USER="" PUBKEY_FILE="" SSH_PORT=22
LOCK_PASSWORD=true GENERATE_PASSWORD=false DRY_RUN=false

usage() { grep -E '^# ' "$0" | sed 's/^# //'; exit 2; }

while getopts ":u:k:p:sPnvh" opt; do
  case "$opt" in
    u) ADMIN_USER=$OPTARG ;;
    k) PUBKEY_FILE=$OPTARG ;;
    p) SSH_PORT=$OPTARG ;;
    s) LOCK_PASSWORD=true ;;
    P) LOCK_PASSWORD=false; GENERATE_PASSWORD=true ;;
    n) DRY_RUN=true ;;
    v) set -x ;;
    h) usage ;;
    *) usage ;;
  esac
done

[[ $EUID -eq 0 ]]               || { error "Run as root."; exit 1; }
[[ $ADMIN_USER && $PUBKEY_FILE ]]|| usage
[[ -r $PUBKEY_FILE ]]           || { error "Cannot read $PUBKEY_FILE"; exit 3; }
[[ $SSH_PORT =~ ^[0-9]{1,5}$ && $SSH_PORT -ge 22 && $SSH_PORT -le 65535 ]] \
                                 || { error "Bad SSH port"; exit 4; }
# Allow leading digit if desired; length ≤ 32
[[ $ADMIN_USER =~ ^[a-z0-9_][a-z0-9_-]{0,31}$ ]] \
                                 || { error "Bad user name"; exit 5; }

###############################################################################
#  Constants
###############################################################################
SSH_HARDEN_FILE="/etc/ssh/sshd_config.d/00-secure.conf"
SYSCTL_FILE="/etc/sysctl.d/99-secure.conf"
SUDOERS_FILE="/etc/sudoers.d/90-${ADMIN_USER}-nopass"
PASSFILE="/root/.${ADMIN_USER}_sudo_password"
BASE_PACKAGES=( openssh-server ufw fail2ban vim vim-runtime tmux ansible
                unattended-upgrades apt-listchanges )
APT_GET="apt-get -o Acquire::Retries=3 -o DPkg::Options::=--force-confdef -y"

###############################################################################
#  Command wrapper (dry-run aware)
###############################################################################
run() {
  if $DRY_RUN; then echo "[DRY] $*"; else "$@"; fi
}

###############################################################################
#  apt wrapper with retries – max 3 total attempts
###############################################################################
apt_retry() {
  local try rc; for try in 1 2 3; do
    run $APT_GET "$@" && return 0
    rc=$?; warn "apt-get $* failed (rc=$rc) – attempt $try/3"
    sleep 2
  done
  error "apt-get $* failed after 3 attempts"; return 10
}

###############################################################################
#  1. System update & packages
###############################################################################
system_update() {
  info "Updating package index…"
  apt_retry -qq update          # keep fully quiet here
  info "Applying upgrades…"
  apt_retry -q upgrade          # -q retains warnings
}
install_packages() {
  info "Installing base packages…"
  apt_retry -q install "${BASE_PACKAGES[@]}"
}

###############################################################################
#  2. Admin account, password & key
###############################################################################
ensure_admin_user() {
  if id "$ADMIN_USER" &>/dev/null; then
    info "User $ADMIN_USER exists."
  else
    info "Creating user $ADMIN_USER…"
    run adduser --disabled-password --gecos "" "$ADMIN_USER"
  fi
  run usermod -aG sudo "$ADMIN_USER"
}

configure_password_policy() {
  # Clean up any previous policy snippet
  run rm -f "$SUDOERS_FILE" || true
  if $LOCK_PASSWORD; then
    info "Locking account password and enabling NOPASSWD sudo…"
    run passwd -l "$ADMIN_USER"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$ADMIN_USER" | run tee "$SUDOERS_FILE" >/dev/null
    run chmod 440 "$SUDOERS_FILE"
  elif $GENERATE_PASSWORD; then
    info "Generating random sudo password (stored root-only)…"
    local pw; pw=$(tr -dc 'A-HJ-NP-Za-km-z2-9' </dev/urandom | head -c22)
    run chpasswd <<<"$ADMIN_USER:$pw"
    umask 177; run printf '%s\n' "$pw" > "$PASSFILE"
    info "Password stored in $PASSFILE"
  fi
}

install_pubkey() {
  info "Installing / updating SSH key…"
  local sshdir="/home/$ADMIN_USER/.ssh"
  run install -o "$ADMIN_USER" -g "$ADMIN_USER" -m700 -d "$sshdir"
  # Append if missing
  if ! (grep -qxFf "$PUBKEY_FILE" "$sshdir/authorized_keys" 2>/dev/null); then
    run cat "$PUBKEY_FILE" >> "$sshdir/authorized_keys"
  fi
  run chown "$ADMIN_USER:$ADMIN_USER" "$sshdir/authorized_keys"
  run chmod 600 "$sshdir/authorized_keys"
}

###############################################################################
#  3. OpenSSH hardening
###############################################################################
secure_ssh() {
  info "Hardening OpenSSH daemon…"
  run install -o root -g root -m644 /dev/null "$SSH_HARDEN_FILE"
  cat <<EOF | run tee "$SSH_HARDEN_FILE" >/dev/null
# managed by secure_debian_server.sh
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
Protocol 2
AllowUsers $ADMIN_USER
EOF
  run systemctl reload ssh
}

###############################################################################
#  4. Firewall & Fail2Ban
###############################################################################
configure_firewall() {
  info "Configuring UFW…"
  # Remove default ssh rules without flushing all rules
  run ufw --force delete allow ssh 2>/dev/null || true
  run ufw --force delete limit ssh 2>/dev/null || true
  # Base policy
  run ufw default deny incoming
  run ufw default allow outgoing
  run ufw limit "$SSH_PORT"/tcp
  run ufw --force enable
}
configure_fail2ban() {
  info "Ensuring Fail2Ban is active…"
  run systemctl enable --now fail2ban
}

###############################################################################
#  5. Unattended security upgrades
###############################################################################
enable_unattended_upgrades() {
  info "Configuring unattended-upgrades…"
  cat <<EOF | run tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

###############################################################################
#  6. Kernel / network hardening
###############################################################################
apply_sysctl_hardening() {
  info "Applying secure sysctl parameters…"
  cat <<'EOF' | run tee "$SYSCTL_FILE" >/dev/null
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
EOF
  run sysctl --system -q
  info "Confirmed ip_forward → $(sysctl -n net.ipv4.ip_forward)"
}

###############################################################################
#  7. Health check
###############################################################################
health_check() {
  info "Running post-hardening health check…"
  if ss -tnlp | grep -q ":$SSH_PORT "; then
    info "SSH is listening on port $SSH_PORT ✔"
  else
    warn "SSH NOT listening on port $SSH_PORT!"
  fi
  # AppArmor presence
  if [[ -d /sys/kernel/security/apparmor ]]; then
    info "AppArmor is enabled (mode: $(aa-status --mode 2>/dev/null || echo 'unknown'))"
  else
    warn "AppArmor not enabled!"
  fi
}

###############################################################################
#  Main
###############################################################################
main() {
  system_update
  install_packages
  ensure_admin_user
  configure_password_policy
  install_pubkey
  secure_ssh
  configure_firewall
  configure_fail2ban
  enable_unattended_upgrades
  apply_sysctl_hardening
  health_check
  info "✅  Hardening complete (dry-run=$DRY_RUN). Admin user: $ADMIN_USER"
}
main


