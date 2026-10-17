# procpeek

Tiny, read-only process forensics for Linux servers. One bash script, nothing to install beyond what a typical VPS already has.

I built it after my control panel's security audit flagged a process as "running from RAM/memfd". I wanted to see for myself what that process was before trusting it or killing it.

## What it does

| Command | What you get |
|---|---|
| `procpeek scan` | Every process running from a deleted binary, from RAM (memfd), or from a world-writable temp folder (`/tmp`, `/var/tmp`, `/dev/shm`) |
| `procpeek ports` | Every listening port with its process, PID and owning package, and whether it is public or local-only |
| `procpeek <PID>` | A full profile of one process |
| `procpeek <name>` | The same, for the oldest process with that name (e.g. `procpeek nginx`) |

It never kills, changes or deletes anything.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Aleksandar0232/procpeek/main/procpeek.sh -o /usr/local/bin/procpeek
chmod +x /usr/local/bin/procpeek
```

Run it as root to see every process.

## Example

These are test processes planted on purpose: one copied into `/dev/shm`, one loaded straight into memory, and one whose binary was deleted after it started.

```text
$ procpeek scan
PID      USER       NAME             VERDICT
250      root       sleepy           runs from a world-writable temp folder
         binary: /dev/shm/sleepy
258      root       3                binary exists only in RAM (memfd), never on disk
         binary: /memfd:evil (deleted)
496      root       gone             binary was deleted and is not owned by any package
         binary: /home/test/gone (deleted)

Dig into one with: procpeek <PID>
```

```text
$ procpeek 258
── PID 258 · 3 ──
  User      root
  State     S (sleeping)
  Started   Sat Oct 17 22:40:07 2026  (running 00:12)
  Memory    1.9 MB
  Command   sleep 302
  Binary    /memfd:evil (deleted)
  Package   not from a package
  Workdir   /home/test
  Service   none (not started by systemd)
  Parents   1:systemd
  Children  0
  Files     3 open
  Network   0 socket(s)

  ⚠ binary exists only in RAM (memfd), never on disk
```

## How the verdicts work

| Verdict | What it means | Usual cause |
|---|---|---|
| ⚠ binary exists only in RAM (memfd) | The program was loaded into an anonymous memory file and never touched the disk | Fileless malware loaders use this trick. Some legitimate software does too (sandboxes, monitoring agents) |
| ⚠ runs from a world-writable temp folder | The binary lives in `/tmp`, `/var/tmp` or `/dev/shm` | A classic place for droppers and miners |
| ⚠ binary was deleted and is not owned by any package | The file was removed after the process started, and no package claims that path | Malware that deletes itself, or a hand-installed tool that was removed |
| ● binary was replaced by an update | A package updated the file on disk, but the old copy is still running | Normal after `yum`/`dnf`/`apt` upgrades. Restart the service (procpeek prints the command) |

A red verdict is a reason to look closer, not proof of compromise. The `Package`, `Script`, `Parents` and `Network` lines in the profile usually tell you which it is.

## What the profile shows

- **User, state, start time, memory**
- **Command** line and the actual **binary** behind it
- **Package** that owns the binary (via `rpm` or `dpkg`)
- **Script**: for interpreted programs (Perl, Python, PHP, bash), the script file being run and its package
- **Service**: the systemd unit it belongs to, if any
- **Parents**: the chain of processes that started it
- **Files** open, including any memfd handles
- **Network**: its sockets, local and remote addresses

## Requirements

- bash 4.4+
- `procps` (`ps`, `pgrep`): present on any normal install
- `iproute` / `iproute2` (`ss`): for `ports` and the network section
- `rpm` or `dpkg`: for package lookups

Written for AlmaLinux / CentOS-family servers running CWP or cPanel. It also works on Debian and Ubuntu.

## License

[MIT](LICENSE)
