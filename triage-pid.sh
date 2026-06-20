#!/usr/bin/env bash
#
# triage-pid.sh — read-only deep-dive triage of a SINGLE process's executable memory.
#
# Where detect-injected-code.sh sweeps every process for injection *signatures*, this script
# takes one <pid> and resolves the *provenance* of each suspicious region — the manual workflow
# from proton-bridge-forensics/docs/01-jit-memory-deep-dive.md, automated for one target:
#
#   1. process context  — binary, path, parent, owner, tracer, seccomp, deleted-exe check
#   2. suspicious maps   — re-classify this pid's executable VMAs (RWX/ANON-X/MEMFD-X/DEL-X/TMP-X/Xstack/heap)
#   3. residency + W^X   — smaps Size/Rss/Pss/dirty + VmFlags per region; flag true write+execute pages
#   4. memfd labels      — self-identifying JIT mappings (e.g. /memfd:JITCode:QtQml)
#   5. disassembly       — first bytes of each anon-exec/rwx region (compiler prologue vs shellcode tells)
#   6. header pointers   — resolve leading 8-byte words of each region to a lib / heap / anon / unmapped
#
# SAFE: opens nothing for write, attaches to nothing, sends no network traffic. Reading another
# process's /proc/<pid>/mem requires root (or same-uid + a permissive yama ptrace_scope); without
# it, steps 1-4 still work and 5-6 are skipped with a note.
#
#   sudo ./triage-pid.sh 11223
#
# Exit code: 0 = inspected, 2 = no such pid / unreadable, 1 = usage.

set -u
shopt -s nullglob

RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; CYN=$'\e[36m'; DIM=$'\e[2m'; BLD=$'\e[1m'; RST=$'\e[0m'
[ -t 1 ] || { RED=; YEL=; GRN=; CYN=; DIM=; BLD=; RST=; }

die()   { echo "${RED}error:${RST} $1" >&2; exit "${2:-1}"; }
hdr()   { echo; echo "${BLD}── $* ${RST}${BLD}$(printf '%.0s─' $(seq 1 $((60 - ${#1}))))${RST}"; }

[ $# -eq 1 ] || die "usage: $0 <pid>" 1
pid=$1
case "$pid" in (*[!0-9]*|'') die "pid must be numeric: '$pid'" 1 ;; esac
proc="/proc/$pid"
[ -d "$proc" ] || die "no such process: pid $pid" 2
# A readable mode bit isn't enough — /proc/<pid>/maps is ptrace-gated; probe a real read.
head -n1 "$proc/maps" >/dev/null 2>&1 || die "cannot read $proc/maps — ptrace-gated (try sudo)" 2

# Resolve a virtual address (hex, no 0x) to the pathname of the mapping it falls in.
resolve_addr() {
    local target lo hi range rest
    target=$((16#$1))
    while IFS= read -r line; do
        range=${line%% *}
        lo=$((16#${range%-*})); hi=$((16#${range#*-}))
        if (( target >= lo && target < hi )); then
            # pathname = field 6+ (may contain spaces); blank => anonymous
            rest=$(awk '{ $1=$2=$3=$4=$5=""; sub(/^ +/,""); print }' <<<"$line")
            printf '%s' "${rest:-<anonymous>}"; return 0
        fi
    done < "$proc/maps"
    printf '<unmapped>'
}

# ── 1. Process context ────────────────────────────────────────────────────────
hdr "1. Process context"
comm=$(tr -d '\n' < "$proc/comm" 2>/dev/null)
exe=$(readlink "$proc/exe" 2>/dev/null || echo '<unreadable — try sudo>')
cmd=$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null); cmd=${cmd% }
uid=$(awk '/^Uid:/{print $2; exit}'        "$proc/status" 2>/dev/null)
ppid=$(awk '/^PPid:/{print $2; exit}'      "$proc/status" 2>/dev/null)
tracer=$(awk '/^TracerPid:/{print $2; exit}' "$proc/status" 2>/dev/null)
seccomp=$(awk '/^Seccomp:/{print $2; exit}'  "$proc/status" 2>/dev/null)
pcomm=""; [ "${ppid:-0}" != 0 ] && pcomm=$(tr -d '\n' 2>/dev/null < "/proc/$ppid/comm")

printf '  %-12s %s\n' "pid"      "$pid ($comm)"
printf '  %-12s %s\n' "exe"      "$exe"
printf '  %-12s %s\n' "cmdline"  "${cmd:-<empty>}"
printf '  %-12s %s%s\n' "owner uid" "${uid:-?}" "$([ "${uid:-x}" = 0 ] && echo "  ${RED}[ROOT]${RST}")"
printf '  %-12s %s\n' "parent"   "${ppid:-?} (${pcomm:-?})"

if [ "${tracer:-0}" != 0 ]; then
    tcomm=$(tr -d '\n' < "/proc/$tracer/comm" 2>/dev/null)
    printf '  %-12s %s\n' "tracer" "${RED}TracerPid=$tracer ($tcomm) — something is attached${RST}"
else
    printf '  %-12s %s\n' "tracer" "${GRN}none (TracerPid 0)${RST}"
fi
printf '  %-12s %s\n' "seccomp" "${seccomp:-?}"
case "$exe" in
    *'(deleted)') printf '  %-12s %s\n' "on-disk" "${RED}exe backing file is DELETED — strong evasion signal${RST}" ;;
esac
if [ -r "$proc/environ" ]; then
    pre=$(tr '\0' '\n' < "$proc/environ" 2>/dev/null | grep '^LD_PRELOAD=')
    [ -n "$pre" ] && printf '  %-12s %s\n' "LD_PRELOAD" "${RED}$pre${RST}"
fi

# ── 2. Suspicious executable mappings ─────────────────────────────────────────
hdr "2. Suspicious executable mappings"
home=${HOME:-/nonexistent-home}
# Collect anon-exec / rwx region starts for the disassembly + pointer steps.
deep_starts=(); deep_tags=()
found_any=0

while IFS= read -r line || [ -n "$line" ]; do
    perms=${line#* }; perms=${perms%% *}
    [ "${perms:2:1}" = x ] || continue
    if [[ $line =~ ^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+(.*)$ ]]; then
        path=${BASH_REMATCH[1]}
    else
        path=""
    fi
    start=${line%%-*}
    w=${perms:1:1}

    case "$path" in
        "[vdso]"|"[vsyscall]"|"[vvar]"|"[uprobes]") continue ;;
    esac

    tag="" ; deep=0
    case "$path" in
        "/memfd:"*|*"/memfd:"*) tag="MEMFD-X"; [ "$w" = w ] && deep=1 ;;
        *"(deleted)")
            case "$path" in
                /usr/lib/*|/lib/*|/usr/lib64/*|/lib64/*|/usr/local/lib/*|/usr/lib32/*)
                    tag="DEL-X ${DIM}(std lib; likely post-upgrade)${RST}" ;;
                *)  tag="${RED}DEL-X (non-standard path — evasion signal)${RST}"; deep=1 ;;
            esac ;;
        /tmp/*|/dev/shm/*|/run/shm/*|"$home"/*) tag="TMP-X"; deep=1 ;;
        "[stack]") tag="XSTACK (executable stack)"; deep=1 ;;
        "[heap]")  tag="XHEAP (executable heap)";   deep=1 ;;
        "")        tag="ANON-X (no file backing)";  deep=1 ;;
    esac
    # A plain file-backed r-x mapping is normal (libraries) — only report it if also writable.
    if [ -z "$tag" ] && [ "$w" = w ]; then tag="RWX (file-backed write+execute)"; deep=1; fi
    [ -z "$tag" ] && continue

    wx=""; [ "$w" = w ] && wx=" ${RED}«W+X»${RST}"
    printf '  %s  %s  %s%s\n' "$perms" "${path:-<anonymous>}" "$tag" "$wx"
    found_any=1
    if [ "$deep" = 1 ]; then deep_starts+=("$start"); deep_tags+=("${path:-<anonymous>}"); fi
done < <(cat "$proc/maps" 2>/dev/null)

[ "$found_any" = 0 ] && echo "  ${GRN}none — no writable, anonymous, memfd, deleted, or tmp-backed executable memory${RST}"

# ── 3. Residency + W^X for each interesting region ────────────────────────────
if [ ${#deep_starts[@]} -gt 0 ] && [ -r "$proc/smaps" ]; then
    hdr "3. Residency + W^X (smaps)"
    echo "  ${DIM}Sparse/low-Rss + W^X-separated views ⇒ legit JIT/pool. Packed + single W+X page ⇒ inspect closely.${RST}"
    for start in "${deep_starts[@]}"; do
        awk -v s="$start" '
            $0 ~ "^" s "-" { p=1 }
            p {
                if ($1 ~ /-/ && NR>1 && seen) exit
                seen=1
                if ($1 ~ /^[0-9a-f]+-/)              hdr=$0
                else if ($1=="Size:")               size=$2" "$3
                else if ($1=="Rss:")                rss=$2" "$3
                else if ($1=="Pss:")                pss=$2" "$3
                else if ($1=="Private_Dirty:")      dirty=$2" "$3
                else if ($1=="VmFlags:")            { flags=$0; sub(/^VmFlags: */,"",flags); done=1 }
            }
            done {
                printf "  %s\n    Size=%s  Rss=%s  Pss=%s  Priv_Dirty=%s\n    VmFlags: %s\n", hdr, size, rss, pss, dirty, flags
                exit
            }
        ' "$proc/smaps"
    done
fi

# ── 4. memfd labels (self-identifying JIT) ────────────────────────────────────
hdr "4. memfd labels (self-identifying runtimes)"
labels=$(awk '$NF ~ /memfd:/ {print $NF}' "$proc/maps" 2>/dev/null | sort | uniq -c | sort -rn)
if [ -n "$labels" ]; then
    echo "$labels" | sed 's/^/  /'
    echo "  ${DIM}A runtime that labels its own pages (e.g. JITCode:QtQml) is almost never an injector.${RST}"
else
    echo "  ${DIM}none — no memfd-named mappings${RST}"
fi

# ── 5 + 6. Disassembly + header-pointer resolution (needs /proc/pid/mem) ───────
# A readable mode bit on /proc/<pid>/mem is not enough — the actual pread is gated by yama
# ptrace_scope. Probe with a real 4-byte read before trusting it.
mem_ok=0
if [ ${#deep_starts[@]} -gt 0 ] && [ -r "$proc/mem" ]; then
    [ "$(dd if="$proc/mem" bs=1 skip=$((16#${deep_starts[0]})) count=4 2>/dev/null | wc -c)" -gt 0 ] && mem_ok=1
fi

if [ ${#deep_starts[@]} -eq 0 ]; then
    : # nothing to disassemble
elif [ "$mem_ok" = 0 ]; then
    hdr "5. Disassembly + pointer resolution"
    echo "  ${YEL}skipped — cannot read $proc/mem (need root, or same-uid + yama ptrace_scope ≤ 1)${RST}"
else
    have_objdump=0; command -v objdump >/dev/null 2>&1 && have_objdump=1
    have_od=0;      command -v od       >/dev/null 2>&1 && have_od=1
    # objdump needs a seekable regular file (not a pipe), and od -j seeking into /proc/<pid>/mem
    # throws I/O errors on non-resident pages — so snapshot each region's head into a temp file
    # via dd (which lseeks then reads sequentially) and analyze that.
    buf=$(mktemp /tmp/triage-pid.XXXXXX) || die "cannot create temp file" 1
    trap 'rm -f "$buf"' EXIT

    for i in "${!deep_starts[@]}"; do
        start=${deep_starts[$i]}; what=${deep_tags[$i]}
        hdr "5+6. Region $start  ($what)"

        dd if="$proc/mem" bs=1 skip=$((16#$start)) count=96 of="$buf" 2>/dev/null
        if [ ! -s "$buf" ]; then
            echo "  ${YEL}first page not resident/readable — nothing to disassemble${RST}"
            continue
        fi

        if [ "$have_objdump" = 1 ]; then
            echo "  ${DIM}first bytes — look for: endbr64 / push rbp (compiler) vs syscall stubs, self-decode loops (shellcode)${RST}"
            objdump -D -b binary -m i386:x86-64 -M intel "$buf" 2>/dev/null \
              | sed -n '8,40p' | sed 's/^/    /'
        else
            echo "  ${YEL}objdump not installed — skipping disassembly${RST}"
        fi

        if [ "$have_od" = 1 ]; then
            echo "  ${CYN}leading 8-byte words resolved (self-referential header ⇒ allocator/pool bookkeeping):${RST}"
            hit=0
            while read -r word; do
                case "$word" in ''|0|0000000000000000) continue ;; esac
                v=${word#"${word%%[!0]*}"}; [ -z "$v" ] && continue
                # only bother resolving plausible userspace pointers
                [ ${#v} -lt 4 ] && continue
                tgt=$(resolve_addr "$v")
                case "$tgt" in
                    '<unmapped>') ;; # skip noise
                    *) printf '    0x%-14s → %s\n' "$v" "$tgt"; hit=1 ;;
                esac
            done < <(od -An -v -tx8 "$buf" 2>/dev/null | tr ' ' '\n')
            [ "$hit" = 0 ] && echo "    ${DIM}(no leading words resolve to a known mapping)${RST}"
        fi
    done
fi

# ── 7. Suggested manual follow-up ─────────────────────────────────────────────
hdr "7. If still unresolved"
cat <<EOF
  ${DIM}Close the last gap with a live debugger (attaches — not read-only):${RST}
    sudo gdb -p $pid -batch -ex 'info proc mappings' -ex 'info symbol <addr>'
    sudo gdb -p $pid -batch -ex 'catch syscall mprotect' -ex 'continue'   # catch the allocator setting PROT_EXEC
  ${DIM}Verify the on-disk binary's authenticity (provenance ≠ memory):${RST}
    dpkg -S "$exe" 2>/dev/null || echo '  not dpkg-tracked — check the vendor update signature'
EOF

exit 0
