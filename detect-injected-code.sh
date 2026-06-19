#!/usr/bin/env bash
#
# detect-injected-code.sh — read-only triage scanner for code-injection / JIT-spray /
# fileless-execution indicators on a Linux host.
#
# For every running process it inspects /proc/<pid>/maps, /status, and /environ and flags
# executable memory that is writable, not backed by a legitimate file, hidden (deleted/memfd),
# or loaded from a writable directory — plus active ptrace relationships and LD_PRELOAD.
#
# SAFE: opens nothing for write, attaches to nothing, sends no network traffic. Run as root for
# full coverage; as a normal user it sees only your own processes.
#
#   sudo ./detect-injected-code.sh            # scan all processes
#   sudo ./detect-injected-code.sh --posture  # only print the host hardening posture
#
# Exit code: 0 = no non-allowlisted findings, 1 = findings present.


set -u
shopt -s nullglob

# Legit-JIT allowlist (by /proc/<pid>/comm). Findings from these are shown as INFO, not ALERT.
#    Allow list is OPTIONAL!!
# Tune per your risk appetite. Anything NOT listed that shows RWX/anon-exec is worth an extra look.
ALLOWLIST_JIT="${ALLOWLIST_JIT:-chrome chromium chromium-browse firefox firefox-bin thunderbird node java mono dotnet python3 ruby mongod erlang Discord gnome-shell gjs Xwayland gnome-software gnome-session-b}"

RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; DIM=$'\e[2m'; BLD=$'\e[1m'; RST=$'\e[0m'
[ -t 1 ] || { RED=; YEL=; GRN=; DIM=; BLD=; RST=; }

posture_only=0
[ "${1:-}" = "--posture" ] && posture_only=1

is_allowlisted() {  # $1 = comm
    local c
    for c in $ALLOWLIST_JIT; do [ "$1" = "$c" ] && return 0; done
    return 1
}

print_posture() {
    echo "${BLD}── Host hardening posture ────────────────────────────────────────${RST}"
    local f v
    for f in kernel/yama/ptrace_scope kernel/kptr_restrict kernel/dmesg_restrict \
             kernel/unprivileged_bpf_disabled kernel/perf_event_paranoid \
             kernel/randomize_va_space vm/unprivileged_userfaultfd; do
        if [ -r "/proc/sys/$f" ]; then
            v=$(cat "/proc/sys/$f" 2>/dev/null)
            printf '  %-38s = %s\n' "${f//\//.}" "$v"
        fi
    done
    # ld.so.preload — global library injection vector
    if [ -s /etc/ld.so.preload ]; then
        echo "  ${RED}/etc/ld.so.preload is NON-EMPTY:${RST}"
        sed 's/^/      /' /etc/ld.so.preload
    elif [ -e /etc/ld.so.preload ]; then
        echo "  ${YEL}/etc/ld.so.preload exists but is empty${RST}"
    else
        echo "  /etc/ld.so.preload                     = ${GRN}absent (good)${RST}"
    fi
    # noexec on writable dirs — kills the TMP-X vector
    local m
    for m in /tmp /dev/shm /run/shm; do
        mountpoint -q "$m" 2>/dev/null || continue
        if findmnt -no OPTIONS "$m" 2>/dev/null | grep -q noexec; then
            printf '  %-38s = %snoexec (good)%s\n' "mount $m" "$GRN" "$RST"
        else
            printf '  %-38s = %sEXEC ALLOWED%s\n' "mount $m" "$YEL" "$RST"
        fi
    done
    echo
}

print_posture
[ "$posture_only" = "1" ] && exit 0

[ "$(id -u)" = "0" ] || echo "${YEL}Note: not root — only your own processes are visible. Re-run with sudo for full coverage.${RST}"
echo "${BLD}── Scanning processes ────────────────────────────────────────────${RST}"

findings=0
infos=0

for procdir in /proc/[0-9]*; do
    pid=${procdir#/proc/}
    [ -r "$procdir/maps" ] || continue
    comm=$(tr -d '\n' < "$procdir/comm" 2>/dev/null) || continue

    # owner uid + tracer
    uid=$(awk '/^Uid:/{print $2; exit}' "$procdir/status" 2>/dev/null)
    tracer=$(awk '/^TracerPid:/{print $2; exit}' "$procdir/status" 2>/dev/null)
    elevated=""; [ "${uid:-x}" = "0" ] && elevated=" ${RED}[ROOT]${RST}"

    hits=()

    # ── ptrace relationship
    [ "${tracer:-0}" != "0" ] && hits+=("TRACED  TracerPid=$tracer (a process is attached to this one)")

    # ── LD_PRELOAD in environment
    if [ -r "$procdir/environ" ]; then
        pre=$(tr '\0' '\n' < "$procdir/environ" 2>/dev/null | grep '^LD_PRELOAD=')
        [ -n "$pre" ] && hits+=("LDPRE   $pre")
    fi

    # ── memory mappings
    while IFS= read -r line || [ -n "$line" ]; do
        perms=${line#* }; perms=${perms%% *}                 # 2nd field
        [ "${perms:2:1}" = "x" ] || continue                 # only executable VMAs matter
        # pathname = everything after the 5th field (inode), captured verbatim so paths
        # containing spaces (e.g. an attacker-named file) are not normalized/collapsed.
        if [[ $line =~ ^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+(.*)$ ]]; then
            path=${BASH_REMATCH[1]}
        else
            path=""                                          # anonymous mapping (no pathname)
        fi
        w=${perms:1:1}

        case "$path" in
            "[vdso]"|"[vsyscall]"|"[vvar]"|"[uprobes]") continue ;;  # legit kernel-provided exec pages
        esac

        # [stack]/[heap] are always writable, so an executable one is always rwx — it
        # would double-report as both RWX and XSTACK/XHEAP below. Suppress the RWX line
        # for them; the dedicated XSTACK/XHEAP tag already carries the W^X finding.
        case "$path" in "[stack]"|"[heap]") sh=1 ;; *) sh=0 ;; esac
        if [ "$w" = "w" ] && [ "$sh" = 0 ]; then
            hits+=("RWX     $perms  ${path:-<anonymous>}")
        elif [ -z "$path" ]; then
            hits+=("ANON-X  $perms  <anonymous executable mapping>")
        fi

        case "$path" in
            # memfd mappings always carry a trailing "(deleted)", so this must be tested
            # BEFORE the generic *"(deleted)" arm or it would never match.
            "/memfd:"*|*"/memfd:"*) hits+=("MEMFD-X $perms  $path") ;;
            *"(deleted)")
                case "$path" in
                    /usr/lib/*|/lib/*|/usr/lib64/*|/lib64/*|/usr/local/lib/*|/usr/lib32/*)
                        # deleted standard library = almost always a post-upgrade artifact, not evasion
                        hits+=("DEL-X   $perms  $path  ${DIM}(post-upgrade; restart proc — needrestart)${RST}") ;;
                    *)  hits+=("DEL-X   $perms  $path  ← ${RED}deleted from NON-standard path (evasion signal)${RST}") ;;
                esac ;;
            /tmp/*|/dev/shm/*|/run/shm/*|"$HOME"/*) hits+=("TMP-X   $perms  $path") ;;
            "[stack]")           hits+=("XSTACK  $perms  executable stack") ;;
            "[heap]")            hits+=("XHEAP   $perms  executable heap") ;;
        esac
    done < <(cat "$procdir/maps" 2>/dev/null)

    [ ${#hits[@]} -eq 0 ] && continue

    if is_allowlisted "$comm"; then
        label="${DIM}INFO (JIT-allowlisted)${RST}"; ((infos++))
    else
        label="${RED}ALERT${RST}"; ((findings++))
    fi
    echo
    echo "  ${BLD}pid $pid${RST} ($comm) uid=${uid:-?}${elevated}  → $label"
    # de-dup identical hit lines
    printf '    %s\n' "${hits[@]}" | sort -u
done

echo
echo "${BLD}── Summary ───────────────────────────────────────────────────────${RST}"
echo "  ALERT  (non-allowlisted): $findings"
echo "  INFO   (allowlisted JIT): $infos"
echo
echo "  ${DIM}Next: triage each ALERT (real injection vs. an undocumented JIT runtime).${RST}"
echo "  ${DIM}Confirm a finding by hand:  sudo pmap -X <pid>   and   cat /proc/<pid>/maps${RST}"

[ "$findings" -gt 0 ] && exit 1 || exit 0
