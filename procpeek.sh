#!/usr/bin/env bash
# procpeek — tiny process forensics for a Linux VPS
#
#   procpeek scan        processes running from deleted files, RAM (memfd) or temp dirs
#   procpeek ports       what is listening, which process owns it, which package it came from
#   procpeek <PID>       full profile of one process
#   procpeek <name>      same, for the oldest process with that name (e.g. procpeek nginx)
#
# Read-only: it never kills, changes or deletes anything. Run as root to see everything.

if [ -t 1 ]; then B=$'\e[1m' R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' C=$'\e[36m' D=$'\e[2m' N=$'\e[0m'
else B='' R='' G='' Y='' C='' D='' N=''; fi

# ---------- helpers ----------
comm_of()  { cat "/proc/$1/comm" 2>/dev/null; }
exe_of()   { readlink "/proc/$1/exe" 2>/dev/null; }
user_of()  { local u; u=$(awk '/^Uid:/{print $2}' "/proc/$1/status" 2>/dev/null); id -nu "$u" 2>/dev/null || echo "${u:-?}"; }
row()      { printf "  ${D}%-9s${N} %s\n" "$1" "$2"; }

pkg_of() {   # which package owns a file (rpm on AlmaLinux/CentOS, dpkg on Debian/Ubuntu)
  local f p
  [ -n "$1" ] && [ -e "$1" ] || return 1
  for f in "$1" "$(readlink -f "$1")"; do       # 2nd try handles /bin -> /usr/bin symlinks
    # some files belong to several packages: keep the first so table rows stay on one line
    if command -v rpm >/dev/null 2>&1 && p=$(rpm -qf "$f" 2>/dev/null); then echo "${p%%$'\n'*}"; return 0; fi
    if command -v dpkg >/dev/null 2>&1; then
      p=$(dpkg -S "$f" 2>/dev/null | head -1 | cut -d: -f1)
      [ -n "$p" ] && { echo "$p"; return 0; }
    fi
  done
  return 1
}

container_of() {  # "name (id)" if the process runs inside a Docker/Podman/containerd container
  local id name
  id=$(grep -oE '(docker|libpod|cri-containerd)[-/:][0-9a-f]{12}' "/proc/$1/cgroup" 2>/dev/null | head -1 | grep -oE '[0-9a-f]{12}$')
  [ -n "$id" ] || return 1
  command -v docker >/dev/null 2>&1 && name=$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null) && name=${name#/}
  echo "${name:+$name }($id)"
}

orig_path() {  # "/usr/bin/perl;6abda560 (deleted)" -> "/usr/bin/perl"
  local f=${1% (deleted)} re=';[0-9a-f]{8}$'
  # rpm writes updates as "file;<8 hex>" then renames them over the original; on some kernels
  # a process still running the old copy then shows that temp name
  [[ $f =~ $re ]] && f=${f%;*}
  echo "$f"
}

judge() {    # $1 = exe link. Prints "LEVEL<TAB>reason" for anything odd, returns 1 if normal
  local exe=$1 base pkg
  case "$exe" in
    "")  return 1 ;;                                    # kernel thread, no binary
    /memfd:*) printf 'RED\tbinary exists only in RAM (memfd), never on disk\n' ;;
    /tmp/*|/var/tmp/*|/dev/shm/*) printf 'RED\truns from a world-writable temp folder\n' ;;
    *" (deleted)")
      base=$(orig_path "$exe")
      if pkg=$(pkg_of "$base"); then
        printf 'YEL\tbinary was replaced by an update (%s), process not restarted yet\n' "$pkg"
      else
        printf 'RED\tbinary was deleted and is not owned by any package\n'
      fi ;;
    *) return 1 ;;
  esac
}

# ---------- scan ----------
scan() {
  local d p exe v lvl why col n=0
  printf "${B}%-8s %-10s %-16s %s${N}\n" PID USER NAME VERDICT
  for d in /proc/[0-9]*; do
    p=${d#/proc/}
    [ "$p" = "$$" ] && continue
    exe=$(exe_of "$p")
    v=$(judge "$exe") || continue
    n=$((n + 1))
    lvl=${v%%$'\t'*}; why=${v#*$'\t'}
    col=$Y; [ "$lvl" = RED ] && col=$R
    printf "%-8s %-10s %-16s ${col}%s${N}\n" "$p" "$(user_of "$p")" "$(comm_of "$p")" "$why"
    printf "${D}%-8s binary: %s${N}\n" "" "$exe"
  done
  if [ "$n" -eq 0 ]; then echo "${G}Nothing odd. Every process runs from a real file on disk.${N}"
  else echo; echo "${D}Dig into one with: procpeek <PID>${N}"; fi
}

# ---------- ports ----------
ports() {
  command -v ss >/dev/null 2>&1 || { echo "ss not found (install iproute)"; return 1; }
  local proto state rq sq local peer rest pid name scope col pkg
  printf "${B}%-5s %-28s %-7s %-7s %-14s %s${N}\n" PROTO ADDRESS SCOPE PID PROCESS PACKAGE
  ss -H -tulnp 2>/dev/null | sort -u -k1,1 -k5,5 | while read -r proto state rq sq local peer rest; do
    pid=$(grep -o 'pid=[0-9]*' <<<"$rest" | head -1 | cut -d= -f2)
    name=$(grep -o '(("[^"]*"' <<<"$rest" | head -1 | cut -d'"' -f2)
    case "$local" in
      127.*|\[::1\]*|::1*|*%lo:*) scope=local;  col=$D ;;
      *)                          scope=PUBLIC; col=$Y ;;
    esac
    pkg=$( [ -n "$pid" ] && pkg_of "$(orig_path "$(exe_of "$pid")")" ) ||
      pkg=$( [ -n "$pid" ] && c=$(container_of "$pid") && echo "container: $c" || echo "-")
    printf "%-5s %-28s ${col}%-7s${N} %-7s %-14s ${D}%s${N}\n" \
      "$proto" "$local" "$scope" "${pid:--}" "${name:--}" "$pkg"
  done
  echo; echo "${D}PUBLIC = reachable from the internet unless the firewall blocks it.${N}"
}

# ---------- profile ----------
profile() {
  local p=$1 s exe cmd cwd script a chain q n fds memfds svc v lvl why kids cont
  [ -d "/proc/$p" ] || { echo "${R}No such PID: $p${N}"; exit 1; }
  s=/proc/$p/status
  exe=$(exe_of "$p")
  cwd=$(readlink "/proc/$p/cwd" 2>/dev/null)
  cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)

  echo "${B}${C}── PID $p · $(comm_of "$p") ──${N}"
  row User    "$(user_of "$p")"
  row State   "$(awk '/^State:/{print $2, $3}' "$s")"
  row Started "$(ps -o lstart= -p "$p" 2>/dev/null | xargs)  (running $(ps -o etime= -p "$p" 2>/dev/null | xargs))"
  row Memory  "$(awk '/^VmRSS:/{printf "%.1f MB", $2/1024}' "$s")"
  row Command "${cmd:-[kernel thread]}"
  row Binary  "${exe:-none}"
  cont=$(container_of "$p")
  if [ -n "$cont" ]; then
    row Container "$cont"
    row Package "n/a (binary lives inside the container's own filesystem)"
  else
    row Package "$(pkg_of "$(orig_path "$exe")" || echo 'not from a package')"
  fi

  # interpreted programs (perl, python, php, bash...) — find the script being run
  # (skipped for containers: their paths point into the container, not the host)
  if [ -z "$cont" ] && [ -r "/proc/$p/cmdline" ]; then
    mapfile -d '' args < "/proc/$p/cmdline" 2>/dev/null
    for a in "${args[@]:1}"; do
      [[ $a == -* ]] && continue
      [[ $a != /* && -n $cwd ]] && a="$cwd/$a"
      [ -f "$a" ] && { script=$a; break; }
    done
    [ -n "${script:-}" ] && row Script "$script ($(pkg_of "$script" || echo 'not from a package'))"
  fi

  row Workdir "${cwd:-?}"
  svc=$(grep -o '[^/]*\.service' "/proc/$p/cgroup" 2>/dev/null | head -1)
  row Service "${svc:-none (not started by systemd)}"

  chain=""; q=$p
  for _ in 1 2 3 4 5 6 7 8; do
    q=$(awk '/^PPid:/{print $2}' "/proc/$q/status" 2>/dev/null)
    [ -n "$q" ] && [ "$q" -gt 0 ] || break
    chain="$chain ← $q:$(comm_of "$q")"
  done
  row Parents "${chain:+${chain# ← }}"
  kids=$(grep -l "^PPid:[[:space:]]*$p\$" /proc/[0-9]*/status 2>/dev/null | wc -l)
  row Children "$kids"

  fds=$(ls "/proc/$p/fd" 2>/dev/null | wc -l)
  memfds=$(ls -l "/proc/$p/fd" 2>/dev/null | grep -c 'memfd:')
  row Files   "$fds open$( [ "$memfds" -gt 0 ] && echo ", ${Y}$memfds of them memfd${N}")"

  if command -v ss >/dev/null 2>&1; then
    n=$(ss -H -tunap 2>/dev/null | grep -c "pid=$p,")
    row Network "$n socket(s)"
    ss -H -tunap 2>/dev/null | grep "pid=$p," | head -8 |
      awk '{printf "            %-4s %-9s %s → %s\n", $1, $2, $5, $6}'
  fi

  echo
  if v=$(judge "$exe"); then
    lvl=${v%%$'\t'*}; why=${v#*$'\t'}
    [ "$lvl" = RED ] && echo "  ${R}${B}⚠ $why${N}" || echo "  ${Y}${B}● $why${N}"
    [ -n "$svc" ] && [ "$lvl" = YEL ] && echo "  ${D}fix: systemctl restart $svc${N}"
  else
    echo "  ${G}${B}✓ runs from a normal file on disk${N}"
  fi
}

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------- main ----------
case "${1:-}" in
  scan)            scan ;;
  ports)           ports ;;
  ''|-h|--help)    usage ;;
  *[!0-9]*)
    p=$(pgrep -o -x -- "$1") || { echo "${R}No process named '$1'${N} (try: procpeek scan, or ps aux | grep $1)"; exit 1; }
    profile "$p"
    others=$(pgrep -x -- "$1" | grep -vx "$p" | xargs)
    [ -n "$others" ] && echo "  ${D}same name, other PIDs: $others${N}"
    ;;
  *)               profile "$1" ;;
esac
