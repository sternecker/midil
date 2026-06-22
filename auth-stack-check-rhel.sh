#!/usr/bin/env bash
#
# auth-stack-check-rhel.sh — integrity check for the Linux authentication stack.
#                           RHEL / Fedora / Rocky / Alma / CentOS (rpm-based).
#
# This is the rpm-based sibling of auth-stack-check.sh (which targets dpkg/Debian).
#
# What it does:
#   1. Verifies the auth-stack PACKAGE files against the rpm database
#      (`rpm -V`, which checks digests natively — no extra tool needed, unlike
#      the Debian side which prefers `debsums`).
#   2. Hard-checks the specific BINARIES Velvet Ant swaps — a finding on any
#      of these is a 🔴, vs. a flagged text/config file which is usually
#      benign update noise.
#   3. Flags any *.so in the PAM security dir that is NOT owned by a package
#      (a dropped rogue module).
#   4. Checks /etc/ld.so.preload is absent/empty (the LD-preload rootkit tell,
#      e.g. QLNX / VoidLink supply-chain rootkits).
#
# Exit codes: 0 = clean · 1 = CRITICAL finding (binary/module) · 2 = warnings only.
#
# Usage:  ./auth-stack-check-rhel.sh
# Run as root for complete coverage (some files are root-readable only).

set -uo pipefail

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; DIM=$'\033[2m'; RST=$'\033[0m'
[ -t 1 ] || { RED=; YEL=; GRN=; DIM=; RST=; }

crit=0
warn=0

note()  { printf '%s\n' "$*"; }
ok()    { printf '  %s✓%s %s\n' "$GRN" "$RST" "$*"; }
flag()  { printf '  %s● CRITICAL%s %s\n' "$RED" "$RST" "$*"; crit=$((crit+1)); }
warning(){ printf '  %s● warn%s %s\n' "$YEL" "$RST" "$*"; warn=$((warn+1)); }

if ! command -v rpm >/dev/null 2>&1; then
  echo "This host is not rpm-based (RHEL/Fedora/Rocky/Alma/CentOS). Use auth-stack-check.sh on Debian/Ubuntu. Aborting." >&2
  exit 3
fi

# Packages that make up the auth stack. On rpm distros the PAM library + modules
# all ship in a single `pam` package; OpenSSH is split base/server/clients.
PKGS=(pam openssh openssh-server openssh-clients)
# Keep only the ones actually installed.
INSTALLED=()
for p in "${PKGS[@]}"; do
  rpm -q "$p" >/dev/null 2>&1 && INSTALLED+=("$p")
done

if [ "${#INSTALLED[@]}" -eq 0 ]; then
  echo "None of the expected auth-stack packages (${PKGS[*]}) are installed. Aborting." >&2
  exit 3
fi

# The binaries Velvet Ant actually replaces — pam_unix.so is resolved via the
# package DB so the multilib path (/usr/lib64 vs /lib64) isn't hard-coded.
PAM_UNIX="$(rpm -ql pam 2>/dev/null | grep -m1 '/pam_unix\.so$' || true)"
SECDIR="$(dirname "${PAM_UNIX:-/usr/lib64/security/pam_unix.so}")"
CRIT_BINS=("$PAM_UNIX" /usr/sbin/sshd /usr/bin/ssh /usr/bin/scp /usr/bin/ssh-keygen)

note "═══════════════════════════════════════════════════════════════════"
note " Auth-stack integrity check (rpm)  ·  $(uname -n)  ·  $(date '+%Y-%m-%d %H:%M')"
note " Velvet Ant / Operation Highland detection (pam_unix.so + OpenSSH)"
note "═══════════════════════════════════════════════════════════════════"
[ "$(id -u)" -eq 0 ] || warning "not running as root — some files may be unreadable; rerun with sudo for full coverage"
note ""
note "Installed auth-stack packages:"
for p in "${INSTALLED[@]}"; do printf '  %s\n' "$(rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n' "$p" 2>/dev/null | head -n1)"; done
note ""

# ── 1. Package-manifest verification ────────────────────────────────────────
# Collect "changed file" paths (and their rpm -V flag string) from `rpm -V`.
# rpm -V line format: "<9 verify chars>[ <attr-marker>] <path>" or "missing  <path>".
# The path always starts with '/', so we slice from the first '/' to keep
# attacker paths containing spaces intact (don't field-split — same invariant
# the sweep relies on).
note "[1] Verifying package files against the rpm database (rpm -V)…"
declare -A CHG_FLAGS
changed=()
while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in
    *' /'*) ;;            # has a path field
    *) continue ;;        # prelink/notice/error chatter with no path — skip
  esac
  path="/${line#*/}"
  flags="${line%%/*}"     # verify chars + attr marker, e.g. "S.5....T.  c " or "missing  "
  CHG_FLAGS["$path"]="$flags"
  changed+=("$path")
done < <(rpm -V "${INSTALLED[@]}" 2>/dev/null)

if [ "${#changed[@]}" -eq 0 ]; then
  ok "all auth-stack package files match the manifest"
else
  for path in "${changed[@]}"; do
    case "$path" in
      *.so|*/sshd|*/ssh|*/scp|*/ssh-keygen|"$SECDIR"/*)
        flag "MODIFIED BINARY/MODULE: $path  ← investigate now (reinstall the package, compare hashes)" ;;
      /etc/*|/usr/share/*)
        warning "changed config/text file: $path  ${DIM}(usually benign — authselect / local edit; confirm contents)${RST}" ;;
      *)
        warning "changed file: $path  ${DIM}(verify it's expected)${RST}" ;;
    esac
  done
fi
note ""

# ── 2. Hard binary checks ───────────────────────────────────────────────────
note "[2] Hard-checking the binaries Velvet Ant swaps…"
for b in "${CRIT_BINS[@]}"; do
  [ -n "$b" ] || continue
  if [ ! -e "$b" ]; then
    note "    ${DIM}(absent: $b)${RST}"; continue
  fi
  pkg="$(rpm -qf --qf '%{NAME}' "$b" 2>/dev/null)"
  if [ -z "$pkg" ]; then
    flag "UNOWNED binary in auth path: $b  ← not provided by any package"
    continue
  fi
  # Was this specific file reported changed by the verify pass above?
  if [ -n "${CHG_FLAGS[$b]+x}" ]; then
    f="${CHG_FLAGS[$b]}"
    case "$f" in
      *missing*) flag "$b ($pkg) — file MISSING from the package payload" ;;
      *5*)       flag "$b ($pkg) — digest (checksum) MISMATCH" ;;
      *)         warning "$b ($pkg) — attributes changed (mode/owner/mtime), digest OK  ${DIM}(often prelink/relabel; confirm)${RST}" ;;
    esac
  else
    ok "$(printf '%-52s' "$b") [$pkg] verified"
  fi
done
note ""

# ── 3. Rogue modules in the PAM security dir ────────────────────────────────
note "[3] Scanning the PAM module dir for unowned *.so  ($SECDIR)…"
rogue=0
if [ -d "$SECDIR" ]; then
  while IFS= read -r so; do
    if ! rpm -qf "$so" >/dev/null 2>&1; then
      flag "unowned module: $so  ← dropped file, not from any package"; rogue=1
    fi
  done < <(find "$SECDIR" -maxdepth 1 -name '*.so' 2>/dev/null)
  [ "$rogue" -eq 0 ] && ok "every *.so in $SECDIR is package-owned"
else
  warning "PAM security dir not found: $SECDIR"
fi
note ""

# ── 4. LD-preload rootkit tell ──────────────────────────────────────────────
note "[4] Checking /etc/ld.so.preload (LD-preload rootkit tell)…"
if [ -s /etc/ld.so.preload ]; then
  flag "/etc/ld.so.preload is NON-EMPTY:"
  sed 's/^/        /' /etc/ld.so.preload
else
  ok "/etc/ld.so.preload absent/empty"
fi
note ""

# ── Verdict ─────────────────────────────────────────────────────────────────
note "═══════════════════════════════════════════════════════════════════"
if [ "$crit" -gt 0 ]; then
  printf ' %sVERDICT: %d CRITICAL finding(s) — investigate before trusting this host.%s\n' "$RED" "$crit" "$RST"
  note "═══════════════════════════════════════════════════════════════════"
  exit 1
elif [ "$warn" -gt 0 ]; then
  printf ' %sVERDICT: clean on binaries; %d warning(s) to review (config/text only).%s\n' "$YEL" "$warn" "$RST"
  note "═══════════════════════════════════════════════════════════════════"
  exit 2
else
  printf ' %sVERDICT: CLEAN — auth stack matches the package database.%s\n' "$GRN" "$RST"
  note "═══════════════════════════════════════════════════════════════════"
  exit 0
fi
