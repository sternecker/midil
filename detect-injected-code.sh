#!/usr/bin/env bash
#
# detect-injected-code.sh - read-only triage scanner for code-injection / JIT-spray /
# fileless-execution indicators on a Linux host.
#
# For every running process it inspects /proc/<pid>/maps, /status, and /environ and flags
# executable memory that is writable, not backed by a legitimate file, hidden (deleted/memfd),
# or loaded from a writable directory - plus active ptrace relationships and LD_PRELOAD.
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

# Shell/interpreter comms whose stdio-on-a-socket is the textbook reverse/bind-shell signature (A1).
SHELL_COMMS="sh bash dash ash zsh ksh csh tcsh busybox python python2 python3 perl ruby lua nc ncat netcat socat awk"

# comm patterns that name a kernel thread; a userland process wearing one is masquerading (A3).
looks_like_kthread() {  # $1 = comm
    case "$1" in
        \[*\]) return 0 ;;                                    # literal ps-style brackets
        kworker/*|kworker|ksoftirqd/*|migration/*|watchdog/*|irq/*|rcu_*|rcuop/*|kthreadd|kswapd*|kcompactd*|khugepaged|kdevtmpfs|kauditd|kblockd|kintegrityd|ksmd|khungtaskd|kthrotld|cpuhp/*|idle_inject/*|scsi_eh_*|nvme-wq|writeback) return 0 ;;
    esac
    return 1
}

print_posture() {
    echo "${BLD}-- Host hardening posture ----------------------------------------${RST}"
    local f v
    for f in kernel/yama/ptrace_scope \
             kernel/unprivileged_bpf_disabled kernel/perf_event_paranoid \
             kernel/randomize_va_space vm/unprivileged_userfaultfd; do
        if [ -r "/proc/sys/$f" ]; then
            v=$(cat "/proc/sys/$f" 2>/dev/null)
            printf '  %-38s = %s\n' "${f//\//.}" "$v"
        fi
    done
    # kptr_restrict / dmesg_restrict (C3) - colored verdict + rationale. These two starve the
    # kernel-symbol and kernel-log address leaks a kernel exploit needs to locate its target first.
    local kp dm
    if [ -r /proc/sys/kernel/kptr_restrict ]; then
        kp=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
        case "$kp" in
            1|2) printf '  %-38s = %s%s (good)%s\n'                  "kernel.kptr_restrict" "$GRN" "$kp" "$RST" ;;
            *)   printf '  %-38s = %s%s (leaks kernel pointers)%s\n' "kernel.kptr_restrict" "$YEL" "${kp:-?}" "$RST" ;;
        esac
    fi
    if [ -r /proc/sys/kernel/dmesg_restrict ]; then
        dm=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
        case "$dm" in
            1) printf '  %-38s = %s1 (good)%s\n'                      "kernel.dmesg_restrict" "$GRN" "$RST" ;;
            *) printf '  %-38s = %s%s (dmesg readable by users)%s\n'  "kernel.dmesg_restrict" "$YEL" "${dm:-?}" "$RST" ;;
        esac
    fi
    printf '    %s-> both starve the kernel-symbol/address leak an exploit needs first%s\n' "$DIM" "$RST"
    # core_pattern (C6) - a "|pipe" handler runs as ROOT on every process crash, a known
    # persistence / privilege-escalation vector unless it's the expected systemd/apport handler.
    if [ -r /proc/sys/kernel/core_pattern ]; then
        local cp cph
        cp=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
        if [ "${cp:0:1}" = "|" ]; then
            cph=${cp#|}; cph=${cph%% *}   # handler program, sans args
            case "$cph" in
                *systemd-coredump|*apport) printf '  %-38s = %spipe -> %s (good)%s\n' "kernel.core_pattern" "$GRN" "$cph" "$RST" ;;
                *)                          printf '  %-38s = %spipe -> %s (runs as root on every crash)%s\n' "kernel.core_pattern" "$YEL" "$cph" "$RST" ;;
            esac
        else
            printf '  %-38s = %s%s%s\n' "kernel.core_pattern" "$DIM" "$cp" "$RST"
        fi
    fi
    # ld.so.preload - global library injection vector
    if [ -s /etc/ld.so.preload ]; then
        echo "  ${RED}/etc/ld.so.preload is NON-EMPTY:${RST}"
        sed 's/^/      /' /etc/ld.so.preload
    elif [ -e /etc/ld.so.preload ]; then
        echo "  ${YEL}/etc/ld.so.preload exists but is empty${RST}"
    else
        echo "  /etc/ld.so.preload                     = ${GRN}absent (good)${RST}"
    fi
    # writable/data mounts - noexec,nosuid,nodev triad (C7). noexec kills the TMP-X vector;
    # nosuid defeats the SUID-implant persistence trick. Only separately-mounted dirs are checked
    # (a dir inheriting the root fs has no options of its own to read).
    local m opts miss flag
    for m in /tmp /dev/shm /run/shm /home /var/tmp; do
        mountpoint -q "$m" 2>/dev/null || continue
        opts=",$(findmnt -no OPTIONS "$m" 2>/dev/null),"
        miss=""
        for flag in noexec nosuid nodev; do
            case "$opts" in *",$flag,"*) ;; *) miss="$miss $flag" ;; esac
        done
        if [ -z "$miss" ]; then
            printf '  %-38s = %snoexec,nosuid,nodev (good)%s\n' "mount $m" "$GRN" "$RST"
        else
            printf '  %-38s = %smissing:%s%s\n' "mount $m" "$YEL" "$miss" "$RST"
        fi
    done
    # /proc hidepid= (C8) - hardens the very surface midil reads (and explains its own non-root
    # coverage limit: with hidepid set, an unprivileged sweep can't see other users' PIDs).
    local pmopts hp
    pmopts=",$(findmnt -no OPTIONS /proc 2>/dev/null),"
    hp=""
    case "$pmopts" in
        *",hidepid=2,"*|*",hidepid=invisible,"*) hp="2/invisible" ;;
        *",hidepid=1,"*|*",hidepid=noaccess,"*)  hp="1/noaccess" ;;
    esac
    if [ -n "$hp" ]; then
        printf '  %-38s = %shidepid=%s (good)%s\n' "mount /proc" "$GRN" "$hp" "$RST"
    else
        printf '  %-38s = %sno hidepid (all PIDs visible)%s\n' "mount /proc" "$YEL" "$RST"
    fi
    # NX stack/heap (C2) - affirmative baseline: read this scanner's own [stack]/[heap] perms as the
    # cheap systemic proxy that a default process gets non-exec memory (per-PID exec stack/heap are
    # still flagged individually in the sweep via XSTACK/XHEAP).
    local seg perms
    for seg in stack heap; do
        perms=$(awk -v s="[$seg]" '$0 ~ s {print $2; exit}' /proc/self/maps 2>/dev/null)
        case "$perms" in
            *x*) printf '  %-38s = %sEXEC%s\n'           "nx-$seg" "$YEL" "$RST" ;;
            ?*)  printf '  %-38s = %snon-exec (good)%s\n' "nx-$seg" "$GRN" "$RST" ;;
        esac
    done
    # boot/kernel trust anchors (C5) - Secure Boot + kernel lockdown
    # Secure Boot: efivar SecureBoot-<global-GUID> is 4 attr bytes + 1 value byte (1=on,0=off)
    if [ ! -d /sys/firmware/efi ]; then
        printf '  %-38s = %slegacy BIOS - no Secure Boot%s\n' "secure-boot" "$YEL" "$RST"
    else
        local sbf sbv
        local -a sbglob=(/sys/firmware/efi/efivars/SecureBoot-*)
        sbf="${sbglob[0]:-}"
        if [ -n "$sbf" ] && [ -r "$sbf" ]; then
            sbv=$(od -An -tu1 -j4 -N1 "$sbf" 2>/dev/null | tr -d ' ')
            case "$sbv" in
                1) printf '  %-38s = %senabled (good)%s\n' "secure-boot" "$GRN" "$RST" ;;
                0) printf '  %-38s = %sdisabled%s\n'       "secure-boot" "$YEL" "$RST" ;;
                *) printf '  %-38s = %sunknown (%s)%s\n'    "secure-boot" "$DIM" "${sbv:-?}" "$RST" ;;
            esac
        else
            printf '  %-38s = %sUEFI, state unreadable (need root)%s\n' "secure-boot" "$DIM" "$RST"
        fi
    fi
    # Kernel lockdown gates /dev/mem, kprobes, and unsigned module load; active mode is the [bracketed] token
    if [ -r /sys/kernel/security/lockdown ]; then
        local lk
        lk=$(cat /sys/kernel/security/lockdown 2>/dev/null)
        lk=${lk#*[}; lk=${lk%%]*}
        case "$lk" in
            integrity|confidentiality) printf '  %-38s = %s%s (good)%s\n' "kernel.lockdown" "$GRN" "$lk" "$RST" ;;
            none)                      printf '  %-38s = %snone%s\n'       "kernel.lockdown" "$YEL" "$RST" ;;
            *)                         printf '  %-38s = %s%s%s\n'         "kernel.lockdown" "$DIM" "${lk:-?}" "$RST" ;;
        esac
    else
        printf '  %-38s = %sunavailable (not built-in)%s\n' "kernel.lockdown" "$DIM" "$RST"
    fi
    # Module integrity (C1) - the Linux kernel-payload delivery path. modules_disabled=1 seals all
    # further module loading; sig_enforce=Y rejects unsigned modules. Pairs with kernel.lockdown.
    local md se cfg
    if [ -r /proc/sys/kernel/modules_disabled ]; then
        md=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)
        case "$md" in
            1) printf '  %-38s = %s1 - module loading sealed (good)%s\n' "kernel.modules_disabled" "$GRN" "$RST" ;;
            *) printf '  %-38s = %s%s - modules can still load%s\n'      "kernel.modules_disabled" "$YEL" "${md:-?}" "$RST" ;;
        esac
    fi
    if [ -r /sys/module/module/parameters/sig_enforce ]; then
        se=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null)
        case "$se" in
            Y) printf '  %-38s = %sY - unsigned modules rejected (good)%s\n' "module.sig_enforce" "$GRN" "$RST" ;;
            *) printf '  %-38s = %s%s - unsigned modules allowed%s\n'        "module.sig_enforce" "$YEL" "${se:-?}" "$RST" ;;
        esac
    else
        # sysfs param absent -> fall back to the kernel build config (read-only)
        cfg="/boot/config-$(uname -r)"
        if [ -r "$cfg" ]; then
            if grep -q '^CONFIG_MODULE_SIG_FORCE=y' "$cfg" 2>/dev/null; then
                printf '  %-38s = %sCONFIG_MODULE_SIG_FORCE=y (good)%s\n'  "module signing" "$GRN" "$RST"
            elif grep -q '^CONFIG_MODULE_SIG=y' "$cfg" 2>/dev/null; then
                printf '  %-38s = %sbuilt, not forced%s\n'                 "module signing" "$DIM" "$RST"
            else
                printf '  %-38s = %sunsigned modules allowed%s\n'          "module signing" "$YEL" "$RST"
            fi
        fi
    fi
    echo
}

print_posture
[ "$posture_only" = "1" ] && exit 0

[ "$(id -u)" = "0" ] || echo "${YEL}Note: not root - only your own processes are visible. Re-run with sudo for full coverage.${RST}"
echo "${BLD}-- Scanning processes --------------------------------------------${RST}"

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
    force_alert=0      # A1/A3 behavioral tells force ALERT past the JIT allowlist
    had_map=0          # set when /proc/<pid>/maps has any line (a real kthread has none)

    # -- ptrace relationship
    [ "${tracer:-0}" != "0" ] && hits+=("TRACED  TracerPid=$tracer (a process is attached to this one)")

    # -- LD_PRELOAD in environment
    if [ -r "$procdir/environ" ]; then
        pre=$(tr '\0' '\n' < "$procdir/environ" 2>/dev/null | grep '^LD_PRELOAD=')
        [ -n "$pre" ] && hits+=("LDPRE   $pre")
    fi

    # -- executable image identity (psaux-style cross-check, AoMF Ch.21)
    # /proc/<pid>/exe is the kernel's authoritative pointer to the running binary; an image running
    # from a writable/world-accessible dir is a drop-and-exec tell (this is the canonical
    # argv[0]="apache2" backed by /tmp/x case). Overlaps the TMP-X mapping line by design - EXE-TMP
    # is the authoritative /proc/exe identity and fires even when no separate suspicious VMA exists.
    # Kernel threads have no exe (readlink fails) and are skipped.
    #
    # A name-vs-path *verdict* (comm/argv[0] vs the on-disk binary) deliberately lives in
    # triage-pid.sh, not here: at sweep altitude it is anti-correlated with the threat - the kernel
    # seeds comm from the exec'd basename, so it stays silent on a real rename yet fires on every
    # legitimate multi-call/symlinked binary (gjs->gjs-console, pipewire-pulse, podman self-reexec
    # as comm="exe"). The deep dive can afford a per-pid dpkg-ownership cross-check; the sweep can't.
    # The one precise rename signal worth a sweep tag - masquerading as a [kworker] kernel thread -
    # is scoped separately as backlog A3.
    if exe=$(readlink "$procdir/exe" 2>/dev/null) && [ -n "$exe" ]; then
        exe_clean=${exe% (deleted)}                       # a dropped binary unlinked after exec
        case "$exe_clean" in
            /tmp/*|/dev/shm/*|/run/shm/*|"$HOME"/*)
                hits+=("EXE-TMP $exe_clean  <- binary image is in a writable dir") ;;
        esac
    fi

    # -- socket-backed stdio backdoor (A1) - reverse/bind shells dup a network socket onto fd 0/1/2.
    # Requiring stdin (fd0) to BE a socket that is also duped onto stdout/stderr rejects the common
    # journald case (socket stdout, but tty/null stdin). A shell/interpreter comm makes it a textbook
    # reverse shell -> force ALERT even if that comm is JIT-allowlisted (e.g. python3); a non-shell
    # comm is left to the normal label (inetd-style socket activation looks identical).
    s0=$(readlink "$procdir/fd/0" 2>/dev/null)
    if [ "${s0#socket:}" != "$s0" ]; then                    # fd0 is socket:[inode]
        s1=$(readlink "$procdir/fd/1" 2>/dev/null)
        s2=$(readlink "$procdir/fd/2" 2>/dev/null)
        if [ "$s0" = "$s1" ] || [ "$s0" = "$s2" ]; then      # same socket duped (dup2 signature)
            case " $SHELL_COMMS " in
                *" $comm "*) hits+=("SOCKSH  fd0=fd{1,2}=$s0  <- ${RED}shell stdio on a socket (reverse/bind shell)${RST}"); force_alert=1 ;;
                *)           hits+=("SOCKSH  fd0=fd{1,2}=$s0  (stdin+stdout share a socket - inetd-style or backdoor)") ;;
            esac
        fi
    fi

    # -- memory mappings
    while IFS= read -r line || [ -n "$line" ]; do
        had_map=1                                            # any maps line => a real address space
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

        # [stack]/[heap] are always writable, so an executable one is always rwx - it
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
                        hits+=("DEL-X   $perms  $path  ${DIM}(post-upgrade; restart proc - needrestart)${RST}") ;;
                    *)  hits+=("DEL-X   $perms  $path  <- ${RED}deleted from NON-standard path (evasion signal)${RST}") ;;
                esac ;;
            /tmp/*|/dev/shm/*|/run/shm/*|"$HOME"/*) hits+=("TMP-X   $perms  $path") ;;
            "[stack]")           hits+=("XSTACK  $perms  executable stack") ;;
            "[heap]")            hits+=("XHEAP   $perms  executable heap") ;;
        esac
    done < <(cat "$procdir/maps" 2>/dev/null)

    # -- fake kernel-thread masquerade (A3) - a kthread-style comm with a real userland footprint
    # (resolvable /proc/<pid>/exe or actual memory mappings); genuine kernel threads have neither an
    # exe link nor a populated address space. Force ALERT - this is never a legit JIT runtime.
    if looks_like_kthread "$comm" && { [ -n "${exe:-}" ] || [ "$had_map" = 1 ]; }; then
        hits+=("FAKETHRD comm='$comm' wears a kernel-thread name but has a userland image/maps")
        force_alert=1
    fi

    [ ${#hits[@]} -eq 0 ] && continue

    if [ "$force_alert" = 0 ] && is_allowlisted "$comm"; then
        label="${DIM}INFO (JIT-allowlisted)${RST}"; ((infos++))
    else
        label="${RED}ALERT${RST}"; ((findings++))
    fi
    echo
    echo "  ${BLD}pid $pid${RST} ($comm) uid=${uid:-?}${elevated}  -> $label"
    # de-dup identical hit lines
    printf '    %s\n' "${hits[@]}" | sort -u
done

echo
echo "${BLD}-- Summary -------------------------------------------------------${RST}"
echo "  ALERT  (non-allowlisted): $findings"
echo "  INFO   (allowlisted JIT): $infos"
echo
echo "  ${DIM}Next: triage each ALERT (real injection vs. an undocumented JIT runtime).${RST}"
echo "  ${DIM}Confirm a finding by hand:  sudo pmap -X <pid>   and   cat /proc/<pid>/maps${RST}"

[ "$findings" -gt 0 ] && exit 1 || exit 0
