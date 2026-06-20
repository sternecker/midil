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

**Run as root** for full coverage (otherwise limited to your own processes). It prints the owning
UID and stars processes running as root, so you immediately see injection *into elevated* targets.

**False positives are expected** from legitimate JIT runtimes — browsers (Chrome/Firefox), Node,
the JVM, .NET/Mono, V8, some Python. The script carries an allowlist that marks
those findings as informational rather than alerts. Tune the allowlist per your risk appetite per host, then anything left
red is worth investigating. The real value is the **inventory**: after a clean run you know exactly
which processes legitimately use RWX/JIT memory — that is the W^X attack surface to harden or
sandbox first.

## Limitations

midil is a **read-only, point-in-time** triage of executable-memory provenance. Several important
attack techniques — code reuse (ret2libc/ROP), W→X page flips, transient/self-repairing payloads,
pointer-redirection, and kernel-mode compromise — produce **no anomalous mapping for it to see**.
A clean run means *"no userland-injected executable memory was resident at snapshot time,"* **not**
*"this host is uncompromised."* 

