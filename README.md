# midil
Memory Injection Detection in Linux

A read-only triage scanner. 
**False positives are expected**  

For every running process it flags:  
| Tag | Indicator | Why it matters |
|-----|-----------|----------------|
| `RWX` | writable **and** executable mapping | classic injection / unsafe JIT (W^X violation) |
| `ANON-X` | executable mapping with **no file backing** (excludes `[vdso]`/`[vsyscall]`) | shellcode, not a library |
| `DEL-X` | executable mapping backed by a **deleted** file | fileless / on-disk evasion |
| `MEMFD-X` | executable mapping backed by `memfd` | fileless execution |
| `TMP-X` | executable mapping from `/tmp`, `/dev/shm`, `/run/shm`, or `$HOME` | code from a writable/world-accessible dir |
| `XSTACK` | executable `[stack]` | exec-stack (NX bypass surface) |
| `XHEAP` | executable `[heap]` | JIT-spray landing pad |
| `TRACED` | `TracerPid != 0` | something is ptrace-attached to it right now |
| `LDPRE` | `LD_PRELOAD` set in the process environment | library injection |
| `EXE-TMP` | `/proc/<pid>/exe` binary image resolves under `/tmp`, `/dev/shm`, `/run/shm`, or `$HOME` | drop-and-exec (the binary itself, not just a mapping) |
| `SOCKSH` | `/proc/<pid>/fd/0` is a `socket:[inode]` duped onto fd 1/2 | reverse/bind shell (a shell `comm` forces ALERT even if JIT-allowlisted) |
| `FAKETHRD` | a kernel-thread-style `comm` (`kworker/…`, `[bracketed]`, …) with a real exe/address space | userland process masquerading as a kernel thread |

**Run as root** for full coverage (otherwise limited to your own processes). It prints the owning
UID and stars processes running as root, so you immediately see injection *into elevated* targets.

**False positives are expected** from legitimate JIT runtimes — browsers (Chrome/Firefox), Node,
the JVM, .NET/Mono, V8, some Python. The script carries an allowlist that marks
those findings as informational rather than alerts. Tune the allowlist per your risk appetite per host, then anything left
red is worth investigating. The real value is the **inventory**: after a clean run you know exactly
which processes legitimately use RWX/JIT memory — that is the W^X attack surface to harden or
sandbox first.

## Host hardening posture

```bash
sudo ./detect-injected-code.sh --posture   # print the host posture, then exit
```

The same posture block prints at the top of every full scan. It reports the host settings that
govern the attack surface above: the relevant sysctls (`yama.ptrace_scope`, `kptr_restrict`,
`dmesg_restrict`, `unprivileged_bpf_disabled`, `perf_event_paranoid`, `randomize_va_space`,
`unprivileged_userfaultfd`), whether `/etc/ld.so.preload` is empty, and whether the writable/data
mounts (`/tmp`, `/dev/shm`, `/run/shm`, `/home`, `/var/tmp`) carry the `noexec,nosuid,nodev` triad
(`noexec` kills the `TMP-X` vector; `nosuid` defeats SUID-implant persistence). It also flags two
runtime-trust knobs: `kernel.core_pattern` when it pipes every crash to a non-standard handler
running as root (a persistence/privesc vector), and `/proc` `hidepid=` (which both hardens the
surface midil reads and explains its own non-root coverage limit).

It gives `kptr_restrict`/`dmesg_restrict` a colored verdict + rationale (they starve the kernel
address leak an exploit needs first), and prints an affirmative `nx-stack`/`nx-heap` baseline
(read from the scanner's own maps — a default process here gets non-executable stack/heap).

It also reports the **boot/kernel trust anchors** beneath midil's visibility:

| Knob | Source | Why it matters |
|------|--------|----------------|
| `secure-boot` | `/sys/firmware/efi/efivars/SecureBoot-*` (UEFI; falls back to a legacy-BIOS note) | anchors the pre-OS code-signing chain; off ⇒ bootkit/early-boot tampering is unguarded |
| `kernel.lockdown` | `/sys/kernel/security/lockdown` | `integrity`/`confidentiality` gate `/dev/mem`, `kprobes`, and unsigned-module loading — the kernel-payload paths midil cannot see |
| `kernel.modules_disabled` + `module.sig_enforce` | `/proc/sys/kernel/modules_disabled`, `/sys/module/module/parameters/sig_enforce` (falls back to `/boot/config-*`) | malicious-module loading is the Linux kernel-payload delivery path; sealed loading / signature enforcement closes it |

These are **hardening signals, not detections** — a strong posture narrows the path to the
kernel/boot blind spot, it never proves the host is clean.

## Limitations

midil is a **read-only, point-in-time** triage of executable-memory provenance. Several important
attack techniques — code reuse (ret2libc/ROP), W→X page flips, transient/self-repairing payloads,
pointer-redirection, and kernel-mode compromise — produce **no anomalous mapping for it to see**.
A clean run means *"no userland-injected executable memory was resident at snapshot time,"* **not**
*"this host is uncompromised."* 

