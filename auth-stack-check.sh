#!/usr/bin/env bash
#
# auth-stack-check.sh - integrity check for the Linux authentication stack.
#
# What it does:
#   1. Verifies the auth-stack PACKAGE files against the dpkg manifest
#      (md5sums). Prefers `debsums` if installed; always falls back to the
#      built-in `dpkg -V` so it works on a stock Debian/Ubuntu box.
#   2. Hard-checks the specific BINARIES Velvet Ant swaps - a finding on any
#      of these is CRITICAL, vs. a flagged text/config file which is usually
#      benign update noise.
#   3. Flags any *.so in the PAM security dir that is NOT owned by a package
#      (a dropped rogue module).
#   4. Checks /etc/ld.so.preload is absent/empty (the LD-preload rootkit tell,
#      e.g. QLNX / VoidLink supply-chain rootkits).
#
# Exit codes: 0 = clean | 1 = CRITICAL finding (binary/module) | 2 = warnings only.
#
# Usage:  ./auth-stack-check.sh
# Run as root for complete coverage (some files are root-readable only).

set -uo pipefail

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; DIM=$'\033[2m'; RST=$'\033[0m'
[ -t 1 ] || { RED=; YEL=; GRN=; DIM=; RST=; }

crit=0
warn=0

note()  { printf '%s\n' "$*"; }
ok()    { printf '  %s+%s %s\n' "$GRN" "$RST" "$*"; }
flag()  { printf '  %s* CRITICAL%s %s\n' "$RED" "$RST" "$*"; crit=$((crit+1)); }
warning(){ printf '  %s* warn%s %s\n' "$YEL" "$RST" "$*"; warn=$((warn+1)); }

if ! command -v dpkg >/dev/null 2>&1; then
  echo "This host is not dpkg-based (Debian/Ubuntu). Aborting." >&2
  exit 3
fi

# Packages that make up the auth stack.
PKGS=(libpam-modules libpam-runtime libpam0g openssh-server openssh-client)
# Keep only the ones actually installed.
INSTALLED=()
for p in "${PKGS[@]}"; do
  dpkg -l "$p" 2>/dev/null | grep -q '^ii' && INSTALLED+=("$p")
done

# The binaries Velvet Ant actually replaces - resolved via the package DB so
# the multiarch path (x86_64/aarch64/...) isn't hard-coded.
PAM_UNIX="$(dpkg -L libpam-modules 2>/dev/null | grep -m1 '/pam_unix\.so$' || true)"
SECDIR="$(dirname "${PAM_UNIX:-/usr/lib/x86_64-linux-gnu/security/pam_unix.so}")"
CRIT_BINS=("$PAM_UNIX" /usr/sbin/sshd /usr/bin/ssh /usr/bin/scp /usr/bin/ssh-keygen)

note "==================================================================="
note " Auth-stack integrity check  |  $(uname -n)  |  $(date '+%Y-%m-%d %H:%M')"
note " Velvet Ant / Operation Highland detection (pam_unix.so + OpenSSH)"
note "==================================================================="
[ "$(id -u)" -eq 0 ] || warning "not running as root - some files may be unreadable; rerun with sudo for full coverage"
note ""
note "Installed auth-stack packages:"
for p in "${INSTALLED[@]}"; do printf '  %s\n' "$(dpkg-query -W -f '${Package} ${Version}' "$p" 2>/dev/null)"; done
note ""

# -- 1. Package-manifest verification ----------------------------------------
# Collect "changed file" paths from debsums (preferred) or dpkg -V (fallback).
note "[1] Verifying package files against the dpkg manifest..."
changed=()
if command -v debsums >/dev/null 2>&1; then
  note "    tool: debsums -c"
  while IFS= read -r line; do
    # debsums -c prints the path of each FAILED file (one per line)
    [ -n "$line" ] && changed+=("$line")
  done < <(debsums -c "${INSTALLED[@]}" 2>/dev/null)
else
  note "    tool: dpkg -V  ${DIM}(install 'debsums' for full content verification)${RST}"
  while IFS= read -r line; do
    # dpkg -V format: "<flags><tab><path>"; flags contain '5' on md5 mismatch
    path="${line#*$'\t'}"; path="${path##* }"
    [ -n "$path" ] && [ "$path" != "$line" -o "${line:0:9}" != "$line" ] && changed+=("$path")
  done < <(dpkg -V "${INSTALLED[@]}" 2>/dev/null)
fi

if [ "${#changed[@]}" -eq 0 ]; then
  ok "all auth-stack package files match the manifest"
else
  for path in "${changed[@]}"; do
    case "$path" in
      *.so|*/sshd|*/ssh|*/scp|*/ssh-keygen|"$SECDIR"/*)
        flag "MODIFIED BINARY/MODULE: $path  <- investigate now (reinstall the package, compare hashes)" ;;
      /usr/share/pam-configs/*|/etc/*)
        warning "changed config file: $path  ${DIM}(usually benign - pam-auth-update / local edit; confirm contents)${RST}" ;;
      *)
        warning "changed file: $path  ${DIM}(verify it's expected)${RST}" ;;
    esac
  done
fi
note ""

# -- 2. Hard binary checks ---------------------------------------------------
note "[2] Hard-checking the binaries Velvet Ant swaps..."
for b in "${CRIT_BINS[@]}"; do
  [ -n "$b" ] || continue
  if [ ! -e "$b" ]; then
    note "    ${DIM}(absent: $b)${RST}"; continue
  fi
  pkg="$(dpkg -S "$b" 2>/dev/null | cut -d: -f1)"
  if [ -z "$pkg" ]; then
    flag "UNOWNED binary in auth path: $b  <- not provided by any package"
    continue
  fi
  # Is this specific file reported changed by the verify pass above?
  hit=0; for c in "${changed[@]:-}"; do [ "$c" = "$b" ] && hit=1; done
  if [ "$hit" -eq 1 ]; then
    flag "$b ($pkg) - checksum MISMATCH"
  else
    ok "$(printf '%-52s' "$b") [$pkg] verified"
  fi
done
note ""

# -- 3. Rogue modules in the PAM security dir --------------------------------
note "[3] Scanning the PAM module dir for unowned *.so  ($SECDIR)..."
rogue=0
if [ -d "$SECDIR" ]; then
  while IFS= read -r so; do
    if ! dpkg -S "$so" >/dev/null 2>&1; then
      flag "unowned module: $so  <- dropped file, not from any package"; rogue=1
    fi
  done < <(find "$SECDIR" -maxdepth 1 -name '*.so' 2>/dev/null)
  [ "$rogue" -eq 0 ] && ok "every *.so in $SECDIR is package-owned"
else
  warning "PAM security dir not found: $SECDIR"
fi
note ""

# -- 4. LD-preload rootkit tell ----------------------------------------------
note "[4] Checking /etc/ld.so.preload (LD-preload rootkit tell)..."
if [ -s /etc/ld.so.preload ]; then
  flag "/etc/ld.so.preload is NON-EMPTY:"
  sed 's/^/        /' /etc/ld.so.preload
else
  ok "/etc/ld.so.preload absent/empty"
fi
note ""

# -- Verdict -----------------------------------------------------------------
note "==================================================================="
if [ "$crit" -gt 0 ]; then
  printf ' %sVERDICT: %d CRITICAL finding(s) - investigate before trusting this host.%s\n' "$RED" "$crit" "$RST"
  note "==================================================================="
  exit 1
elif [ "$warn" -gt 0 ]; then
  printf ' %sVERDICT: clean on binaries; %d warning(s) to review (config/text only).%s\n' "$YEL" "$warn" "$RST"
  note "==================================================================="
  exit 2
else
  printf ' %sVERDICT: CLEAN - auth stack matches the package database.%s\n' "$GRN" "$RST"
  note "==================================================================="
  exit 0
fi
