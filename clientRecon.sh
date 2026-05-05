#!/usr/bin/env bash
# clientRecon.sh
# MSP environment reconnaissance script for Linux and macOS
# Detects platform, runs interactive menu, supports quick and deep scan modes
# Usage: ./clientRecon.sh

set -u

# ---------- Globals ----------
SCRIPT_VERSION="0.4"
OS_TYPE=""
OS_NAME=""
ELEVATED=0
TIME_WINDOW="24h"   # default for log queries
OUTPUT_FILE=""
EXPORT_MODE=0

# ---------- Color helpers ----------
if [ -t 1 ]; then
    C_RESET="\033[0m"
    C_BOLD="\033[1m"
    C_GREEN="\033[32m"
    C_YELLOW="\033[33m"
    C_RED="\033[31m"
    C_CYAN="\033[36m"
    C_BLUE="\033[34m"
else
    C_RESET=""; C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""; C_BLUE=""
fi

# ---------- Output helpers ----------
emit() {
    # Prints to screen and (if export enabled) to file
    local msg="$*"
    echo -e "$msg"
    if [ "$EXPORT_MODE" -eq 1 ] && [ -n "$OUTPUT_FILE" ]; then
        # Strip color codes for file
        echo -e "$msg" | sed -E 's/\x1B\[[0-9;]*[mK]//g' >> "$OUTPUT_FILE"
    fi
}

section() {
    emit ""
    emit "${C_BOLD}${C_CYAN}=== $* ===${C_RESET}"
}

ok()   { emit "${C_GREEN}[OK]${C_RESET} $*"; }
warn() { emit "${C_YELLOW}[!]${C_RESET}  $*"; }
err()  { emit "${C_RED}[X]${C_RESET}  $*"; }
info() { emit "${C_BLUE}[i]${C_RESET}  $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------- Static port lookup ----------
# Returns service name for well-known and common app ports
port_name() {
    case "$1" in
        20|21)    echo "ftp" ;;
        22)       echo "ssh" ;;
        23)       echo "telnet" ;;
        25)       echo "smtp" ;;
        53)       echo "dns" ;;
        67)       echo "dhcp-server" ;;
        68)       echo "dhcp-client" ;;
        69)       echo "tftp" ;;
        80)       echo "http" ;;
        88)       echo "kerberos" ;;
        110)      echo "pop3" ;;
        111)      echo "rpcbind" ;;
        119)      echo "nntp" ;;
        123)      echo "ntp" ;;
        135)      echo "msrpc" ;;
        137|138)  echo "netbios" ;;
        139)      echo "netbios-ssn" ;;
        143)      echo "imap" ;;
        161|162)  echo "snmp" ;;
        389)      echo "ldap" ;;
        443)      echo "https" ;;
        445)      echo "smb" ;;
        465)      echo "smtps" ;;
        514)      echo "syslog" ;;
        515)      echo "lpd" ;;
        587)      echo "smtp-submission" ;;
        631)      echo "ipp/cups" ;;
        636)      echo "ldaps" ;;
        873)      echo "rsync" ;;
        989|990)  echo "ftps" ;;
        993)      echo "imaps" ;;
        995)      echo "pop3s" ;;
        1080)     echo "socks" ;;
        1194)     echo "openvpn" ;;
        1433)     echo "mssql" ;;
        1521)     echo "oracle" ;;
        1701)     echo "l2tp" ;;
        1723)     echo "pptp" ;;
        1883)     echo "mqtt" ;;
        2049)     echo "nfs" ;;
        2375|2376) echo "docker" ;;
        3000)     echo "node/dev-server" ;;
        3128)     echo "squid-proxy" ;;
        3306)     echo "mysql/mariadb" ;;
        3389)     echo "rdp" ;;
        4000)     echo "dev-server" ;;
        4444)     echo "krb524/metasploit" ;;
        5000)     echo "upnp/flask" ;;
        5060|5061) echo "sip" ;;
        5353)     echo "mdns" ;;
        5432)     echo "postgresql" ;;
        5601)     echo "kibana" ;;
        5900)     echo "vnc" ;;
        5984)     echo "couchdb" ;;
        6379)     echo "redis" ;;
        6443)     echo "kubernetes-api" ;;
        6667)     echo "irc" ;;
        7474|7687) echo "neo4j" ;;
        8000)     echo "http-alt/dev" ;;
        8008|8080) echo "http-alt" ;;
        8086)     echo "influxdb" ;;
        8096)     echo "jellyfin" ;;
        8123)     echo "home-assistant" ;;
        8200)     echo "vault" ;;
        8443)     echo "https-alt" ;;
        8888)     echo "jupyter" ;;
        9000)     echo "portainer/php-fpm" ;;
        9090)     echo "prometheus/cockpit" ;;
        9091)     echo "transmission" ;;
        9100)     echo "node-exporter/printer" ;;
        9200)     echo "elasticsearch" ;;
        11211)    echo "memcached" ;;
        11434)    echo "ollama" ;;
        15672)    echo "rabbitmq-mgmt" ;;
        19999)    echo "netdata" ;;
        25565)    echo "minecraft" ;;
        27017)    echo "mongodb" ;;
        32400)    echo "plex" ;;
        51820)    echo "wireguard" ;;
        *)        echo "" ;;
    esac
}

# ---------- Standard service allowlist ----------
# Services that ship with the distro/OS by default. Anything not matching is flagged as non-standard.
is_standard_service() {
    local svc="$1"
    case "$svc" in
        # systemd core
        systemd-*|dbus*|polkit*|user@*|getty@*|serial-getty@*|run-*) return 0 ;;
        # common Linux base services
        accounts-daemon|acpid|atd|auditd|avahi-daemon|chrony|chronyd|cron|crond|cups|cups-browsed) return 0 ;;
        gdm|getty|haveged|irqbalance|kerneloops|lightdm|ModemManager|NetworkManager|NetworkManager-*) return 0 ;;
        nscd|ntp|ntpd|plymouth*|rsyslog|sddm|smartd|ssh|sshd|systemd|thermald|udisks2|upower) return 0 ;;
        wpa_supplicant|unattended-upgrades|apparmor|snapd|networkd-dispatcher|packagekit|polkitd) return 0 ;;
        rpcbind|rpc-*|nfs-*|gpu-manager|whoopsie|kerneloops) return 0 ;;
        # macOS — anything in com.apple namespace is system
        com.apple.*) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------- Detection ----------
detect_os() {
    local uname_s
    uname_s="$(uname -s 2>/dev/null || echo unknown)"
    case "$uname_s" in
        Linux)
            OS_TYPE="linux"
            if [ -r /etc/os-release ]; then
                # shellcheck disable=SC1091
                . /etc/os-release
                OS_NAME="${PRETTY_NAME:-Linux}"
            else
                OS_NAME="Linux"
            fi
            ;;
        Darwin)
            OS_TYPE="macos"
            OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
            ;;
        *)
            OS_TYPE="unknown"
            OS_NAME="$uname_s"
            ;;
    esac
}

detect_privileges() {
    if [ "$(id -u)" -eq 0 ]; then
        ELEVATED=1
    else
        ELEVATED=0
    fi
}

# ---------- Banner ----------
banner() {
    clear
    emit "${C_BOLD}${C_CYAN}"
    emit "============================================================"
    emit "  MSP Environment Recon  v${SCRIPT_VERSION}"
    emit "  Host: $(hostname 2>/dev/null || echo unknown)"
    emit "  OS:   ${OS_NAME}  (${OS_TYPE})"
    if [ "$ELEVATED" -eq 1 ]; then
        emit "  Privilege: ${C_GREEN}ELEVATED (root)${C_CYAN}"
    else
        emit "  Privilege: ${C_YELLOW}standard user${C_CYAN}"
    fi
    emit "  Time:  $(date)"
    emit "============================================================"
    emit "${C_RESET}"
}

# ---------- Quick info modules ----------
mod_system_basics() {
    section "System Basics"
    emit "  $(printf '%-12s: %s' 'Hostname' "$(hostname 2>/dev/null)")"
    emit "  $(printf '%-12s: %s' 'Uptime' "$(uptime 2>/dev/null | sed -E 's/.*up +([^,]+,? *[^,]*),.*load.*/\1/' | sed 's/^ *//')")"
    if [ "$OS_TYPE" = "linux" ]; then
        emit "  $(printf '%-12s: %s' 'Distro' "${OS_NAME}")"
    fi
    emit "  $(printf '%-12s: %s' 'Kernel' "$(uname -r 2>/dev/null)")"
    emit "  $(printf '%-12s: %s' 'Arch' "$(uname -m 2>/dev/null)")"
    if [ "$OS_TYPE" = "macos" ]; then
        emit "  $(printf '%-12s: %s' 'Model' "$(sysctl -n hw.model 2>/dev/null)")"
    fi
    mod_pkg_summary
    mod_cron_summary
    mod_priv_users_summary
}

mod_network_config() {
    section "Network Configuration"
    if [ "$OS_TYPE" = "linux" ] && have ip; then
        emit "${C_BOLD}Interfaces (ip):${C_RESET}"
        ip -brief addr 2>/dev/null | awk '$1 != "lo"' | while read -r line; do emit "  $line"; done
        emit ""
        emit "${C_BOLD}Routes:${C_RESET}"
        ip route 2>/dev/null | while read -r line; do emit "  $line"; done
    elif [ "$OS_TYPE" = "macos" ] || ! have ip; then
        emit "${C_BOLD}Interfaces (ifconfig):${C_RESET}"
        # Only show interfaces with an inet address, exclude loopback
        ifconfig 2>/dev/null | awk '
            /^[a-z0-9]+:/ { iface=$1; sub(/:$/, "", iface) }
            /inet / && iface && iface != "lo0" && iface != "lo" { print "  " iface " " $2; iface="" }
        ' | while read -r line; do emit "$line"; done
        emit ""
        emit "${C_BOLD}Default route:${C_RESET}"
        if have route; then
            route -n get default 2>/dev/null | awk '/gateway|interface/ {print "  " $0}' | while read -r l; do emit "$l"; done
        fi
    fi

    # Active vs inactive adapter check (the wired-vs-wifi gotcha)
    emit ""
    emit "${C_BOLD}Adapter status:${C_RESET}"
    if [ "$OS_TYPE" = "linux" ] && have ip; then
        ip -brief link 2>/dev/null | awk '$1 != "lo" {printf "  %-15s %s\n", $1, $2}' | while read -r l; do emit "$l"; done
    elif [ "$OS_TYPE" = "macos" ]; then
        if have networksetup; then
            networksetup -listallhardwareports 2>/dev/null | awk '
                /Hardware Port/ {port=$0; sub(/Hardware Port: /,"",port)}
                /^Device:/ {dev=$2; print "  " dev " (" port ")"}
            ' | while read -r l; do emit "$l"; done
        fi
    fi
}

mod_dns_info() {
    section "DNS Configuration"
    if [ "$OS_TYPE" = "linux" ]; then
        if [ -r /etc/resolv.conf ]; then
            grep -E '^(nameserver|search|domain)' /etc/resolv.conf 2>/dev/null \
                | while read -r l; do emit "  $l"; done
        fi
        # Detect if local resolver is in use
        if grep -qE '^nameserver\s+127\.' /etc/resolv.conf 2>/dev/null; then
            warn "Local resolver detected (127.x.x.x) — DNS may be served locally"
        fi
    elif [ "$OS_TYPE" = "macos" ]; then
        if have scutil; then
            scutil --dns 2>/dev/null | grep -E 'nameserver|search domain' | sort -u \
                | while read -r l; do emit "  $l"; done
        fi
    fi

    # Quick resolution test
    if have getent; then
        if getent hosts example.com >/dev/null 2>&1; then ok "DNS resolution working (example.com)"; else err "DNS resolution failed for example.com"; fi
    elif have host; then
        if host -W 2 example.com >/dev/null 2>&1; then ok "DNS resolution working (example.com)"; else err "DNS resolution failed for example.com"; fi
    elif have nslookup; then
        if nslookup -timeout=2 example.com >/dev/null 2>&1; then ok "DNS resolution working (example.com)"; else err "DNS resolution failed for example.com"; fi
    fi
}

mod_internet_check() {
    section "Internet Connectivity"
    # External IP
    local ext_ip=""
    if have curl; then
        ext_ip="$(curl -s --max-time 4 https://ifconfig.me 2>/dev/null)"
    fi
    if [ -n "$ext_ip" ]; then emit "External IP : $ext_ip"; else warn "Could not determine external IP"; fi

    # Hop count to 1.1.1.1 (quick, capped)
    if have traceroute; then
        local hops
        hops=$(traceroute -n -w 1 -q 1 -m 8 1.1.1.1 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
        emit "Hops to 1.1.1.1 (max 8): $hops"
    fi

    # Ping gateway
    local gw=""
    if [ "$OS_TYPE" = "linux" ] && have ip; then
        gw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')
    elif [ "$OS_TYPE" = "macos" ] && have route; then
        gw=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
    fi
    if [ -n "$gw" ]; then
        if ping -c 1 -W 2 "$gw" >/dev/null 2>&1 || ping -c 1 -t 2 "$gw" >/dev/null 2>&1; then
            ok "Gateway $gw reachable"
        else
            err "Gateway $gw not reachable"
        fi
    fi
}

mod_domain_info() {
    section "Domain / Auth Context"
    local found=0

    # Active Directory join via realmd
    if have realm; then
        local realm_out
        realm_out=$(realm list 2>/dev/null)
        if [ -n "$realm_out" ]; then
            emit "$realm_out" | while read -r l; do emit "  $l"; done
            found=1
        fi
    fi

    # Samba / workgroup
    if [ -r /etc/samba/smb.conf ]; then
        local wg
        wg=$(awk -F= '/^\s*workgroup/ {gsub(/ /,"",$2); print $2; exit}' /etc/samba/smb.conf 2>/dev/null)
        [ -n "$wg" ] && { emit "Samba workgroup: $wg"; found=1; }
    fi

    # LDAP / SSSD
    [ -r /etc/sssd/sssd.conf ] && { info "SSSD configured (/etc/sssd/sssd.conf present)"; found=1; }
    [ -r /etc/ldap/ldap.conf ] && { info "LDAP client config present (/etc/ldap/ldap.conf)"; found=1; }
    [ -r /etc/openldap/ldap.conf ] && { info "OpenLDAP client config present"; found=1; }

    # macOS directory binding
    if [ "$OS_TYPE" = "macos" ] && have dsconfigad; then
        local ad_out
        ad_out=$(dsconfigad -show 2>/dev/null)
        if [ -n "$ad_out" ]; then emit "$ad_out" | while read -r l; do emit "  $l"; done; found=1; fi
    fi

    [ "$found" -eq 0 ] && info "No domain/directory binding detected — likely standalone/workgroup"
}

mod_users() {
    section "Local Users (non-system)"
    if [ -r /etc/passwd ]; then
        # Show users with UID >= 1000 on Linux, >= 500 on macOS
        local min_uid=1000
        [ "$OS_TYPE" = "macos" ] && min_uid=500
        awk -F: -v m=$min_uid '$3 >= m && $3 < 65534 {printf "  %-20s uid=%-6s shell=%s home=%s\n", $1, $3, $7, $6}' /etc/passwd \
            | while read -r l; do emit "$l"; done
    fi
}

mod_listening_ports() {
    section "Listening Ports"
    local raw=""
    if have ss; then
        raw=$(ss -tulnH 2>/dev/null | awk '{print $1, $5}')
    elif have netstat; then
        if [ "$OS_TYPE" = "macos" ]; then
            raw="$(netstat -an -p tcp 2>/dev/null | awk '/LISTEN/ {print "tcp", $4}')
$(netstat -an -p udp 2>/dev/null | awk 'NR>2 {print "udp", $4}')"
        else
            raw=$(netstat -tulnp 2>/dev/null | tail -n +3 | awk '{print $1, $4}')
        fi
    else
        warn "No ss/netstat available"
        return
    fi

    # Annotate each line: extract port number, look up name
    echo "$raw" | head -n 40 | while read -r proto addr; do
        [ -z "$proto" ] && continue
        # Pull port off the end of addr (handles ipv4:port and [ipv6]:port)
        local port="${addr##*:}"
        local name
        name=$(port_name "$port")
        if [ -n "$name" ]; then
            emit "  $(printf '%-5s %-25s → %s' "$proto" "$addr" "$name")"
        else
            emit "  $(printf '%-5s %s' "$proto" "$addr")"
        fi
    done
    [ "$ELEVATED" -eq 0 ] && info "Process names for ports may be hidden without root"
}

mod_firewall() {
    section "Firewall Status"
    if [ "$OS_TYPE" = "linux" ]; then
        if have ufw; then
            ufw status 2>/dev/null | head -n 5 | while read -r l; do emit "  $l"; done
        elif have firewall-cmd; then
            emit "  firewalld state: $(firewall-cmd --state 2>/dev/null)"
        elif have iptables; then
            if [ "$ELEVATED" -eq 1 ]; then
                local rules
                rules=$(iptables -S 2>/dev/null | wc -l | tr -d ' ')
                emit "  iptables rules loaded: $rules"
            else
                info "iptables requires root to enumerate"
            fi
        fi
    elif [ "$OS_TYPE" = "macos" ]; then
        if have /usr/libexec/ApplicationFirewall/socketfilterfw; then
            local state
            state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
            emit "  $state"
        fi
        if [ "$ELEVATED" -eq 1 ] && have pfctl; then
            local pf
            pf=$(pfctl -s info 2>/dev/null | head -n 2)
            emit "  pf: $pf"
        fi
    fi
}

mod_services() {
    section "Service Status"
    if [ "$OS_TYPE" = "linux" ] && have systemctl; then
        local nonstd_file std_file
        nonstd_file=$(mktemp 2>/dev/null) || return
        std_file=$(mktemp 2>/dev/null) || { rm -f "$nonstd_file"; return; }

        systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
            | awk '{print $1}' | while read -r svc; do
                # Strip .service suffix for matching
                local short="${svc%.service}"
                if is_standard_service "$short"; then
                    echo "  $svc" >> "$std_file"
                else
                    echo "  $svc" >> "$nonstd_file"
                fi
            done

        if [ -s "$nonstd_file" ]; then
            emit "${C_BOLD}${C_YELLOW}Non-standard (added/installed):${C_RESET}"
            head -n 20 "$nonstd_file" | while read -r l; do emit "$l"; done
            emit ""
        fi
        if [ -s "$std_file" ]; then
            emit "${C_BOLD}Standard (system):${C_RESET}"
            head -n 20 "$std_file" | while read -r l; do emit "$l"; done
        fi
        rm -f "$nonstd_file" "$std_file"

        local failed
        failed=$(systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | wc -l | tr -d ' ')
        if [ "$failed" -gt 0 ]; then
            emit ""
            err "$failed failed service(s):"
            systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null \
                | awk '{print "    " $1}' | while read -r l; do emit "$l"; done
        fi
    elif [ "$OS_TYPE" = "macos" ] && have launchctl; then
        local nonstd_file std_file
        nonstd_file=$(mktemp 2>/dev/null) || return
        std_file=$(mktemp 2>/dev/null) || { rm -f "$nonstd_file"; return; }

        launchctl list 2>/dev/null | awk 'NR>1 && $1 != "-" {print $3}' | while read -r svc; do
            if is_standard_service "$svc"; then
                echo "  $svc" >> "$std_file"
            else
                echo "  $svc" >> "$nonstd_file"
            fi
        done

        if [ -s "$nonstd_file" ]; then
            emit "${C_BOLD}${C_YELLOW}Non-standard (added/installed):${C_RESET}"
            head -n 20 "$nonstd_file" | while read -r l; do emit "$l"; done
            emit ""
        fi
        if [ -s "$std_file" ]; then
            local sc
            sc=$(wc -l < "$std_file" | tr -d ' ')
            emit "${C_BOLD}Standard (system):${C_RESET} $sc Apple/system jobs loaded"
        fi
        rm -f "$nonstd_file" "$std_file"

        # Show jobs with non-zero exit (column 2) — sign of recent failure
        local failing
        failing=$(launchctl list 2>/dev/null | awk 'NR>1 && $2 != "0" && $2 != "-" {print "    " $3 " (exit " $2 ")"}')
        if [ -n "$failing" ]; then
            emit ""
            warn "Jobs with non-zero last-exit:"
            echo "$failing" | while read -r l; do emit "$l"; done
        fi
    fi
}

mod_shares() {
    section "Network Shares / Mounts"
    if have mount; then
        mount 2>/dev/null | grep -E 'cifs|smb|nfs|afp' | while read -r l; do emit "  $l"; done
    fi
    # Mounted but failing? Show df errors
    df -h 2>&1 | grep -i 'stale\|denied' | while read -r l; do warn "$l"; done
}

mod_disk() {
    section "Disk Space"
    df -h 2>/dev/null | awk 'NR==1 || $1 !~ /^(tmpfs|devfs|map|overlay)/' | while read -r l; do emit "  $l"; done
}

mod_ram() {
    section "Memory"
    if [ "$OS_TYPE" = "linux" ] && have free; then
        # free -h is already nicely column-aligned — just indent each line
        free -h 2>/dev/null | sed 's/^/  /' | while IFS= read -r l; do emit "$l"; done
    elif [ "$OS_TYPE" = "macos" ]; then
        local total
        total=$(sysctl -n hw.memsize 2>/dev/null)
        if [ -n "$total" ] && have vm_stat; then
            local page_size pages_free pages_active pages_wired pages_compressed
            page_size=$(vm_stat 2>/dev/null | awk '/page size of/ {print $8}')
            [ -z "$page_size" ] && page_size=4096
            pages_free=$(vm_stat 2>/dev/null | awk '/Pages free/ {gsub(/\./,"",$3); print $3}')
            pages_active=$(vm_stat 2>/dev/null | awk '/Pages active/ {gsub(/\./,"",$3); print $3}')
            pages_wired=$(vm_stat 2>/dev/null | awk '/Pages wired down/ {gsub(/\./,"",$4); print $4}')
            pages_compressed=$(vm_stat 2>/dev/null | awk '/Pages occupied by compressor/ {gsub(/\./,"",$5); print $5}')
            local total_gb free_gb used_gb
            total_gb=$(awk -v t="$total" 'BEGIN{printf "%.1f", t/1024/1024/1024}')
            free_gb=$(awk -v p="${pages_free:-0}" -v s="$page_size" 'BEGIN{printf "%.1f", p*s/1024/1024/1024}')
            used_gb=$(awk -v a="${pages_active:-0}" -v w="${pages_wired:-0}" -v c="${pages_compressed:-0}" -v s="$page_size" \
                'BEGIN{printf "%.1f", (a+w+c)*s/1024/1024/1024}')
            emit "  $(printf '%-10s %10s' 'Total' "${total_gb} GB")"
            emit "  $(printf '%-10s %10s' 'Used'  "${used_gb} GB")"
            emit "  $(printf '%-10s %10s' 'Free'  "${free_gb} GB")"
        fi
    fi
}

mod_lan_discovery() {
    section "LAN Discovery (ARP cache + neighbors)"
    if have ip; then
        ip neigh 2>/dev/null | awk '$0 !~ /FAILED|INCOMPLETE/' | while read -r l; do emit "  $l"; done
    elif have arp; then
        arp -an 2>/dev/null | head -n 30 | while read -r l; do emit "  $l"; done
    fi
    info "ARP cache only shows hosts already communicated with — for full sweep use deep mode"
}

# ---------- Package manager helpers ----------
# Detect installed package manager. Returns "apt", "dnf", "yum", "zypper", "pacman", "apk", "macos", or ""
detect_pkg_mgr() {
    if [ "$OS_TYPE" = "macos" ]; then echo "macos"; return; fi
    if have apt && [ -d /var/log/apt ]; then echo "apt"; return; fi
    if have dnf; then echo "dnf"; return; fi
    if have yum && [ ! "$(have dnf && echo 1)" ]; then echo "yum"; return; fi
    if have zypper; then echo "zypper"; return; fi
    if have pacman; then echo "pacman"; return; fi
    if have apk; then echo "apk"; return; fi
    echo ""
}

# Human-readable "X ago" from epoch seconds
epoch_ago() {
    local then="$1"
    [ -z "$then" ] && { echo "unknown"; return; }
    local now diff
    now=$(date +%s)
    diff=$((now - then))
    if [ "$diff" -lt 0 ]; then echo "in the future?"; return; fi
    if [ "$diff" -lt 3600 ]; then echo "$((diff/60))m ago"; return; fi
    if [ "$diff" -lt 86400 ]; then echo "$((diff/3600))h ago"; return; fi
    echo "$((diff/86400))d ago"
}

# Quick one-line summary of last refresh + last upgrade
mod_pkg_summary() {
    local mgr
    mgr=$(detect_pkg_mgr)
    [ -z "$mgr" ] && { emit "  Package mgr : (none detected)"; return; }

    local refresh_ago="unknown" upgrade_ago="unknown"

    case "$mgr" in
        apt)
            # Last metadata refresh: mtime of /var/cache/apt/pkgcache.bin or /var/lib/apt/periodic/update-success-stamp
            local stamp=""
            for f in /var/lib/apt/periodic/update-success-stamp /var/cache/apt/pkgcache.bin; do
                [ -r "$f" ] && { stamp=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null); break; }
            done
            refresh_ago=$(epoch_ago "$stamp")
            # Last upgrade: most recent "upgrade" or "install" entry in history.log
            if [ -r /var/log/apt/history.log ]; then
                local last_up
                last_up=$(grep -E '^Start-Date' /var/log/apt/history.log 2>/dev/null | tail -n 1 | awk '{print $2" "$3}')
                if [ -n "$last_up" ]; then
                    local up_epoch
                    up_epoch=$(date -d "$last_up" +%s 2>/dev/null)
                    upgrade_ago=$(epoch_ago "$up_epoch")
                fi
            fi
            ;;
        dnf|yum)
            # dnf/yum history works without root for read
            local last_line
            last_line=$($mgr history 2>/dev/null | awk 'NR>2 && $1 ~ /^[0-9]+$/ {print; exit}')
            if [ -n "$last_line" ]; then
                local d
                d=$(echo "$last_line" | awk -F'|' '{print $3}' | sed 's/^ *//;s/ *$//')
                local up_epoch
                up_epoch=$(date -d "$d" +%s 2>/dev/null)
                upgrade_ago=$(epoch_ago "$up_epoch")
            fi
            # Refresh stamp on dnf
            local rstamp=""
            for f in /var/cache/dnf/last_makecache /var/cache/dnf; do
                [ -e "$f" ] && { rstamp=$(stat -c %Y "$f" 2>/dev/null); break; }
            done
            refresh_ago=$(epoch_ago "$rstamp")
            ;;
        zypper)
            if [ -r /var/log/zypp/history ]; then
                local last_inst
                last_inst=$(grep -E '\|install\||\|remove\||\|update\|' /var/log/zypp/history 2>/dev/null | tail -n 1 | awk -F'|' '{print $1}')
                if [ -n "$last_inst" ]; then
                    local up_epoch
                    up_epoch=$(date -d "$last_inst" +%s 2>/dev/null)
                    upgrade_ago=$(epoch_ago "$up_epoch")
                fi
            fi
            local rstamp
            rstamp=$(stat -c %Y /var/cache/zypp 2>/dev/null)
            refresh_ago=$(epoch_ago "$rstamp")
            ;;
        pacman)
            if [ -r /var/log/pacman.log ]; then
                local last_up
                last_up=$(grep -E '\[ALPM\] (upgraded|installed)' /var/log/pacman.log 2>/dev/null | tail -n 1 | awk -F'[][]' '{print $2}')
                if [ -n "$last_up" ]; then
                    local up_epoch
                    up_epoch=$(date -d "$last_up" +%s 2>/dev/null)
                    upgrade_ago=$(epoch_ago "$up_epoch")
                fi
                # pacman -Sy (refresh) shows up as "synchronizing package lists"
                local last_sync
                last_sync=$(grep -E 'synchronizing package lists' /var/log/pacman.log 2>/dev/null | tail -n 1 | awk -F'[][]' '{print $2}')
                if [ -n "$last_sync" ]; then
                    local sync_epoch
                    sync_epoch=$(date -d "$last_sync" +%s 2>/dev/null)
                    refresh_ago=$(epoch_ago "$sync_epoch")
                fi
            fi
            ;;
        apk)
            if [ -r /var/log/apk.log ]; then
                local last_apk
                last_apk=$(stat -c %Y /var/log/apk.log 2>/dev/null)
                upgrade_ago=$(epoch_ago "$last_apk")
            fi
            local rstamp
            rstamp=$(stat -c %Y /var/cache/apk 2>/dev/null)
            refresh_ago=$(epoch_ago "$rstamp")
            ;;
        macos)
            if have softwareupdate; then
                local last_su
                last_su=$(softwareupdate --history 2>/dev/null | awk 'NR>2 {print; }' | tail -n 1)
                if [ -n "$last_su" ]; then
                    upgrade_ago=$(echo "$last_su" | awk '{print $(NF-1), $NF}')
                fi
            fi
            refresh_ago="(softwareupdate)"
            ;;
    esac

    emit "  Package mgr : ${mgr} — last refresh: ${refresh_ago}, last upgrade: ${upgrade_ago}"
}

# Verbose package update history (deep scan / menu)
mod_pkg_verbose() {
    section "Package History (last 10 transactions)"
    local mgr
    mgr=$(detect_pkg_mgr)
    [ -z "$mgr" ] && { info "No package manager detected"; return; }
    emit "Detected: $mgr"
    emit ""
    case "$mgr" in
        apt)
            if [ -r /var/log/apt/history.log ]; then
                grep -E '^(Start-Date|Commandline)' /var/log/apt/history.log 2>/dev/null | tail -n 20 \
                    | while read -r l; do emit "  $l"; done
            else
                info "/var/log/apt/history.log not readable"
            fi
            ;;
        dnf|yum)
            $mgr history 2>/dev/null | head -n 14 | while read -r l; do emit "  $l"; done
            ;;
        zypper)
            if [ -r /var/log/zypp/history ]; then
                tail -n 30 /var/log/zypp/history 2>/dev/null | while read -r l; do emit "  $l"; done
            fi
            ;;
        pacman)
            if [ -r /var/log/pacman.log ]; then
                grep -E '\[ALPM\] (upgraded|installed|removed)' /var/log/pacman.log 2>/dev/null \
                    | tail -n 20 | while read -r l; do emit "  $l"; done
            fi
            ;;
        apk)
            [ -r /var/log/apk.log ] && tail -n 20 /var/log/apk.log 2>/dev/null | while read -r l; do emit "  $l"; done
            ;;
        macos)
            softwareupdate --history 2>/dev/null | while read -r l; do emit "  $l"; done
            ;;
    esac
}

# ---------- Cron / scheduled jobs ----------
# Standard cron entry / timer allowlist
is_standard_cron() {
    local entry="$1"
    case "$entry" in
        anacron|apt-daily*|apt-compat|cron-apt|dpkg|logrotate|man-db|mlocate|locate|popularity-contest) return 0 ;;
        ntp|certbot|fstrim|sysstat|update-motd|0anacron|0yum-*|raid-check|mdadm|smartmontools) return 0 ;;
        # systemd timers
        systemd-tmpfiles*|man-db.timer|fstrim.timer|logrotate.timer|apt-daily*.timer) return 0 ;;
        anacron.timer|fwupd-refresh.timer|motd-news.timer|e2scrub_all.timer|dpkg-db-backup.timer) return 0 ;;
        unattended-upgrades*|update-notifier-*|ua-*|ubuntu-advantage*) return 0 ;;
        *) return 1 ;;
    esac
}

# Quick one-line summary
mod_cron_summary() {
    local sys_count=0 timer_count=0 user_count=0 nonstd=0
    local entries

    # System cron files
    if [ -r /etc/crontab ]; then
        sys_count=$(grep -cE '^[^#[:space:]]' /etc/crontab 2>/dev/null || echo 0)
    fi
    if [ -d /etc/cron.d ]; then
        local d_count
        d_count=$(find /etc/cron.d -type f 2>/dev/null | wc -l | tr -d ' ')
        sys_count=$((sys_count + d_count))
    fi

    # systemd timers
    if have systemctl; then
        timer_count=$(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | wc -l | tr -d ' ')
    fi

    # User crontab
    if have crontab; then
        user_count=$(crontab -l 2>/dev/null | grep -cE '^[^#[:space:]]')
    fi

    # Non-standard count: scan /etc/cron.d filenames + systemd timer names
    if [ -d /etc/cron.d ]; then
        for f in /etc/cron.d/*; do
            [ -e "$f" ] || continue
            local name
            name=$(basename "$f")
            is_standard_cron "$name" || nonstd=$((nonstd + 1))
        done
    fi
    if have systemctl; then
        while read -r tname; do
            [ -z "$tname" ] && continue
            is_standard_cron "$tname" || nonstd=$((nonstd + 1))
        done < <(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $NF}')
    fi

    if [ "$nonstd" -gt 0 ]; then
        emit "  Scheduled   : ${sys_count} system cron, ${timer_count} systemd timers, ${user_count} user crontab — ${C_YELLOW}${nonstd} non-standard${C_RESET}"
    else
        emit "  Scheduled   : ${sys_count} system cron, ${timer_count} systemd timers, ${user_count} user crontab"
    fi
}

# Verbose cron listing
mod_cron_verbose() {
    section "Scheduled Jobs (cron + timers)"
    local nonstd_file std_file
    nonstd_file=$(mktemp 2>/dev/null) || return
    std_file=$(mktemp 2>/dev/null) || { rm -f "$nonstd_file"; return; }

    # System crontab
    if [ -r /etc/crontab ]; then
        echo "  [/etc/crontab]" >> "$std_file"
        grep -E '^[^#[:space:]]' /etc/crontab 2>/dev/null | while read -r l; do echo "    $l" >> "$std_file"; done
    fi

    # /etc/cron.d/*
    if [ -d /etc/cron.d ]; then
        for f in /etc/cron.d/*; do
            [ -e "$f" ] || continue
            local name
            name=$(basename "$f")
            local target="$std_file"
            is_standard_cron "$name" || target="$nonstd_file"
            echo "  [/etc/cron.d/$name]" >> "$target"
            grep -E '^[^#[:space:]]' "$f" 2>/dev/null | while read -r l; do echo "    $l" >> "$target"; done
        done
    fi

    # cron.{hourly,daily,weekly,monthly}
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] || continue
        local listing
        listing=$(ls "$d" 2>/dev/null)
        [ -z "$listing" ] && continue
        echo "  [$d]" >> "$std_file"
        echo "$listing" | while read -r f; do echo "    $f" >> "$std_file"; done
    done

    # systemd timers
    if have systemctl; then
        echo "" >> "$std_file"
        echo "  [systemd timers]" >> "$std_file"
        systemctl list-timers --all --no-pager --no-legend 2>/dev/null | while read -r line; do
            local tname
            tname=$(echo "$line" | awk '{print $NF}')
            local target="$std_file"
            is_standard_cron "$tname" || target="$nonstd_file"
            echo "    $line" >> "$target"
        done
    fi

    # User crontab
    if have crontab; then
        local uc
        uc=$(crontab -l 2>/dev/null)
        if [ -n "$uc" ]; then
            echo "" >> "$nonstd_file"
            echo "  [user crontab: $(whoami)]" >> "$nonstd_file"
            echo "$uc" | grep -E '^[^#[:space:]]' | while read -r l; do echo "    $l" >> "$nonstd_file"; done
        fi
    fi

    if [ -s "$nonstd_file" ]; then
        emit "${C_BOLD}${C_YELLOW}Non-standard:${C_RESET}"
        cat "$nonstd_file" | while read -r l; do emit "$l"; done
        emit ""
    fi
    if [ -s "$std_file" ]; then
        emit "${C_BOLD}Standard (system):${C_RESET}"
        cat "$std_file" | while read -r l; do emit "$l"; done
    fi
    rm -f "$nonstd_file" "$std_file"

    [ "$ELEVATED" -eq 0 ] && info "Other users' crontabs require root to enumerate"
}

# ---------- Privileged users ----------
mod_priv_users_summary() {
    local groups_to_check="sudo wheel admin"
    local results=""
    for g in $groups_to_check; do
        local members
        members=$(getent group "$g" 2>/dev/null | awk -F: '{print $4}')
        # macOS dscl fallback for admin group
        if [ -z "$members" ] && [ "$OS_TYPE" = "macos" ] && have dscl && [ "$g" = "admin" ]; then
            members=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //' | tr ' ' ',')
        fi
        if [ -n "$members" ]; then
            local count
            count=$(echo "$members" | awk -F, '{print NF}')
            results="${results}${g}: ${count} (${members})  "
        fi
    done
    if [ -n "$results" ]; then
        emit "  Privileged  : ${results}"
    else
        emit "  Privileged  : (none found in sudo/wheel/admin)"
    fi
}

mod_priv_users_verbose() {
    section "Privileged Users (sudo / wheel / admin)"
    local groups_to_check="sudo wheel admin"
    for g in $groups_to_check; do
        local members
        members=$(getent group "$g" 2>/dev/null | awk -F: '{print $4}')
        if [ -z "$members" ] && [ "$OS_TYPE" = "macos" ] && have dscl && [ "$g" = "admin" ]; then
            members=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //' | tr ' ' ',')
        fi
        if [ -n "$members" ]; then
            emit "  ${C_BOLD}Group ${g}:${C_RESET}"
            echo "$members" | tr ',' '\n' | while read -r u; do
                [ -n "$u" ] && emit "    $u"
            done
        fi
    done

    # Sudoers files (root-only)
    if [ "$ELEVATED" -eq 1 ]; then
        emit ""
        emit "  ${C_BOLD}/etc/sudoers includes:${C_RESET}"
        grep -E '^[^#]' /etc/sudoers 2>/dev/null | grep -v '^$' | while read -r l; do emit "    $l"; done
        if [ -d /etc/sudoers.d ]; then
            for f in /etc/sudoers.d/*; do
                [ -e "$f" ] || continue
                emit "  ${C_BOLD}$(basename "$f"):${C_RESET}"
                grep -E '^[^#]' "$f" 2>/dev/null | grep -v '^$' | while read -r l; do emit "    $l"; done
            done
        fi
    else
        info "Run with sudo to see /etc/sudoers contents"
    fi
}

# ---------- Deep modules ----------
mod_recent_events() {
    section "Recent System Events ($TIME_WINDOW)"
    local since=""
    case "$TIME_WINDOW" in
        24h)   since="-1d" ;;
        48h)   since="-2d" ;;
        week)  since="-7d" ;;
        all)   since="" ;;
    esac

    if [ "$OS_TYPE" = "linux" ] && have journalctl; then
        local jflag="--since=24 hours ago"
        case "$TIME_WINDOW" in
            48h)  jflag="--since=2 days ago" ;;
            week) jflag="--since=7 days ago" ;;
            all)  jflag="" ;;
        esac
        if [ "$ELEVATED" -eq 1 ]; then
            # shellcheck disable=SC2086
            journalctl -p err -b $jflag --no-pager 2>/dev/null | tail -n 30 | while read -r l; do emit "  $l"; done
        else
            info "journalctl shows limited results without root"
            # shellcheck disable=SC2086
            journalctl -p err $jflag --no-pager --user 2>/dev/null | tail -n 20 | while read -r l; do emit "  $l"; done
        fi
    elif [ "$OS_TYPE" = "macos" ] && have log; then
        local mflag="1d"
        case "$TIME_WINDOW" in
            48h)  mflag="2d" ;;
            week) mflag="7d" ;;
            all)  mflag="30d" ;;   # cap at 30d to keep it sane
        esac
        log show --predicate 'messageType == error' --last "$mflag" --style compact 2>/dev/null \
            | tail -n 30 | while read -r l; do emit "  $l"; done
    fi
}

mod_lan_sweep() {
    section "LAN Sweep (ping subnet)"
    # Get primary subnet
    local cidr=""
    if [ "$OS_TYPE" = "linux" ] && have ip; then
        cidr=$(ip -4 -brief addr 2>/dev/null | awk '$1 != "lo" && $2 == "UP" && $3 != "" {print $3; exit}')
    elif [ "$OS_TYPE" = "macos" ]; then
        # Find primary interface from default route, then its IP/mask
        local iface
        iface=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
        if [ -n "$iface" ]; then
            local ip mask
            ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet / {print $2; exit}')
            mask=$(ifconfig "$iface" 2>/dev/null | awk '/inet / {print $4; exit}')
            # Convert hex netmask to /N if possible (24 only — most common case)
            if [ -n "$ip" ] && [ "$mask" = "0xffffff00" ]; then
                cidr="${ip}/24"
            elif [ -n "$ip" ]; then
                cidr="${ip}/24"  # assume /24 as fallback
            fi
        fi
    fi
    if [ -z "$cidr" ]; then
        warn "Could not auto-detect primary subnet; skipping sweep"
        return
    fi
    local base
    base=$(echo "$cidr" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3}')
    emit "Sweeping ${base}.1-254 (this takes ~10s)..."
    for i in $(seq 1 254); do
        ( ping -c 1 -W 1 "${base}.${i}" >/dev/null 2>&1 || ping -c 1 -t 1 "${base}.${i}" >/dev/null 2>&1 ) &
    done
    wait

    # Build IP/MAC list from neighbors, then resolve hostnames
    local raw=""
    if have ip; then
        raw=$(ip neigh 2>/dev/null | awk '$0 ~ /REACHABLE|STALE|DELAY/ {print $1, $5}')
    elif have arp; then
        raw=$(arp -an 2>/dev/null | awk '{gsub(/[()]/,"",$2); print $2, $4}')
    fi

    emit ""
    printf "  %-16s %-18s %s\n" "IP" "MAC" "HOSTNAME" | while read -r l; do emit "$l"; done
    echo "$raw" | while read -r ip mac; do
        [ -z "$ip" ] && continue
        local host=""
        # Reverse DNS, fast timeout
        if have getent; then
            host=$(timeout 1 getent hosts "$ip" 2>/dev/null | awk '{print $2}')
        fi
        if [ -z "$host" ] && have host; then
            host=$(host -W 1 "$ip" 2>/dev/null | awk '/pointer/ {print $NF; exit}' | sed 's/\.$//')
        fi
        if [ -z "$host" ] && have nslookup; then
            host=$(nslookup -timeout=1 "$ip" 2>/dev/null | awk '/name =/ {print $NF; exit}' | sed 's/\.$//')
        fi
        # Fallback to NetBIOS if available
        if [ -z "$host" ] && have nmblookup; then
            host=$(timeout 1 nmblookup -A "$ip" 2>/dev/null | awk '/<00>/ && !/<GROUP>/ {print $1; exit}')
        fi
        [ -z "$host" ] && host="-"
        emit "  $(printf '%-16s %-18s %s' "$ip" "$mac" "$host")"
    done
}

mod_help() {
    clear
    emit "${C_BOLD}${C_CYAN}"
    emit "============================================================"
    emit "  clientRecon — How to Use"
    emit "  v${SCRIPT_VERSION}"
    emit "============================================================"
    emit "${C_RESET}"
    emit ""
    emit "${C_BOLD}WHAT IT DOES${C_RESET}"
    emit "  Fast environmental snapshot of the local system and"
    emit "  surrounding network. Built for MSP triage — walk into a"
    emit "  client site, run it, get oriented in under a minute."
    emit ""
    emit "${C_BOLD}STARTUP${C_RESET}"
    emit "  [1/F/Enter]  Quick scan (default — universal baseline)"
    emit "  [2/D]        Deep scan (quick + verbose package/cron/users +"
    emit "               events + LAN ping sweep)"
    emit "  [3/S]        Menu (run individual modules)"
    emit "  [0/Q]        Quit Recon Tool"
    emit ""
    emit "${C_BOLD}MODES${C_RESET}"
    emit "  ${C_BOLD}Quick${C_RESET}: system basics (with package mgr / cron / privileged"
    emit "         user summary lines), network, DNS, internet, domain,"
    emit "         users, ports, firewall, services, shares, disk, RAM, ARP."
    emit "         Runs in seconds. Suitable for first-touch triage."
    emit "  ${C_BOLD}Deep${C_RESET}:  Quick scan + verbose package history + full cron/timer"
    emit "         listing + sudoers/wheel detail + recent error events"
    emit "         (24h/48h/week/all) + active subnet ping sweep with"
    emit "         hostname resolution. Takes 10–30s."
    emit ""
    emit "${C_BOLD}PRIVILEGES${C_RESET}"
    emit "  Runs without root. Some checks (full event logs, all"
    emit "  iptables rules, process names tied to ports) need root."
    emit "  Tip: if you know you'll need full data, just start with sudo:"
    emit "      ${C_CYAN}sudo ./clientRecon.sh${C_RESET}"
    emit ""
    emit "${C_BOLD}OUTPUT${C_RESET}"
    emit "  Default is screen-only. After a scan completes, hit [a] to"
    emit "  save a timestamped text file in the current directory:"
    emit "      ${C_CYAN}clientRecon-{hostname}-{YYYYMMDD-HHMMSS}.txt${C_RESET}"
    emit "  Color codes are stripped from the file."
    emit ""
    emit "${C_BOLD}SERVICES SECTION${C_RESET}"
    emit "  Non-standard services (likely added by user/apps) are listed"
    emit "  on top in yellow. Standard system services are listed below."
    emit "  Failed services (systemd) are flagged separately."
    emit ""
    emit "${C_BOLD}LISTENING PORTS${C_RESET}"
    emit "  Annotated with common service names where known"
    emit "  (e.g. 22 → ssh, 11434 → ollama, 32400 → plex)."
    emit ""
    emit "${C_BOLD}LAN SWEEP (deep mode or menu)${C_RESET}"
    emit "  Pings every host on the primary /24, then resolves IP → MAC →"
    emit "  hostname (reverse DNS, with NetBIOS fallback if nmblookup is"
    emit "  available). Hosts not registered anywhere show '-' for hostname."
    emit ""
    emit "${C_BOLD}TIME WINDOWS (events)${C_RESET}"
    emit "  Last 24h (default), 48h, week, or all. macOS 'all' is capped"
    emit "  at 30 days for performance."
    emit ""
    emit "${C_BOLD}PLATFORMS${C_RESET}"
    emit "  Auto-detects Linux vs macOS via uname. PowerShell counterpart"
    emit "  for Windows lives separately as clientRecon.ps1."
    emit ""
    printf "Press Enter to return to menu... "
    read -r _
}

# ---------- Menus ----------
prompt_time_window() {
    emit ""
    emit "Select time window for log queries:"
    emit "  ${C_BOLD}[1/F/Enter]${C_RESET}  Last 24 hours"
    emit "  ${C_BOLD}[2/D]${C_RESET}        Last 48 hours"
    emit "  ${C_BOLD}[3/S]${C_RESET}        Last week"
    emit "  ${C_BOLD}[4/A]${C_RESET}        All (slow)"
    printf "Choice: "
    read -r choice
    case "$choice" in
        ""|1|f|F) TIME_WINDOW="24h" ;;
        2|d|D)    TIME_WINDOW="48h" ;;
        3|s|S)    TIME_WINDOW="week" ;;
        4|a|A)    TIME_WINDOW="all" ;;
        *)        TIME_WINDOW="24h" ;;
    esac
}

prompt_export() {
    printf "Export results to text file? [y/N]: "
    read -r choice
    case "$choice" in
        y|Y)
            EXPORT_MODE=1
            OUTPUT_FILE="./clientRecon-$(hostname 2>/dev/null)-$(date +%Y%m%d-%H%M%S).txt"
            : > "$OUTPUT_FILE"
            info "Exporting to $OUTPUT_FILE"
            ;;
    esac
}

prompt_elevate() {
    if [ "$ELEVATED" -eq 0 ]; then
        emit ""
        warn "Some checks require root for full data."
        printf "Re-run with sudo? [y/N]: "
        read -r choice
        case "$choice" in
            y|Y)
                exec sudo -E "$0" "$@"
                ;;
        esac
    fi
}

run_quick_scan() {
    banner
    mod_system_basics
    mod_network_config
    mod_dns_info
    mod_internet_check
    mod_domain_info
    mod_users
    mod_listening_ports
    mod_firewall
    mod_services
    mod_shares
    mod_disk
    mod_ram
    mod_lan_discovery
    section "Quick scan complete"
    [ "$EXPORT_MODE" -eq 1 ] && info "Saved to $OUTPUT_FILE"
}

run_deep_scan() {
    run_quick_scan
    mod_pkg_verbose
    mod_cron_verbose
    mod_priv_users_verbose
    mod_recent_events
    mod_lan_sweep
    section "Deep scan complete"
}

main_menu() {
    while true; do
        emit ""
        emit "${C_BOLD}Main Menu${C_RESET}"
        emit "  ${C_BOLD}[1/F/Enter]${C_RESET}  Quick scan"
        emit "  ${C_BOLD}[2/D]${C_RESET}        Deep scan (with time window)"
        emit "  ${C_BOLD}[3/S]${C_RESET}        Services only"
        emit "  ${C_BOLD}[4/A]${C_RESET}        LAN sweep only"
        emit "  ${C_BOLD}[5/W]${C_RESET}        Network config only"
        emit "  ${C_BOLD}[6/E]${C_RESET}        Help"
        emit "  ${C_BOLD}[0/Q]${C_RESET}        Quit Recon Tool"
        printf "Choice: "
        read -r choice
        case "$choice" in
            ""|1|f|F) run_quick_scan ;;
            2|d|D)    prompt_time_window; run_deep_scan ;;
            3|s|S)    mod_services ;;
            4|a|A)    mod_lan_sweep ;;
            5|w|W)    mod_network_config ;;
            6|e|E)    mod_help ;;
            0|q|Q)    exit 0 ;;
            *)        warn "Invalid choice" ;;
        esac
    done
}

prompt_startup() {
    emit ""
    emit "${C_BOLD}[1/F/Enter]${C_RESET}  Quick scan"
    emit "${C_BOLD}[2/D]${C_RESET}        Deep scan"
    emit "${C_BOLD}[3/S]${C_RESET}        Menu"
    emit "${C_BOLD}[0/Q]${C_RESET}        Quit Recon Tool"
    printf "Choice: "
    read -r choice
    case "$choice" in
        ""|1|f|F) return 0 ;;   # quick
        2|d|D)    return 1 ;;   # deep
        3|s|S)    return 2 ;;   # menu
        0|q|Q)    exit 0 ;;
        *)        return 0 ;;
    esac
}

prompt_post_scan() {
    while true; do
        emit ""
        emit "${C_BOLD}[1/S/Enter]${C_RESET}  Menu"
        emit "${C_BOLD}[2/A]${C_RESET}        Save to file"
        emit "${C_BOLD}[0/Q]${C_RESET}        Quit Recon Tool"
        printf "Choice: "
        read -r choice
        case "$choice" in
            ""|1|s|S) main_menu; return ;;
            2|a|A)
                if [ "$EXPORT_MODE" -eq 1 ]; then
                    info "Already saved to $OUTPUT_FILE"
                else
                    EXPORT_MODE=1
                    OUTPUT_FILE="./clientRecon-$(hostname 2>/dev/null)-$(date +%Y%m%d-%H%M%S).txt"
                    : > "$OUTPUT_FILE"
                    # Re-run quick scan to capture into file (output already shown on screen)
                    run_quick_scan >/dev/null
                    info "Saved to $OUTPUT_FILE"
                fi
                ;;
            0|q|Q)    exit 0 ;;
            *)        warn "Invalid choice" ;;
        esac
    done
}

# ---------- Entry ----------
detect_os
detect_privileges

if [ "$OS_TYPE" = "unknown" ]; then
    err "Unsupported OS: $OS_NAME"
    exit 1
fi

banner
prompt_startup
action=$?

case "$action" in
    0) run_quick_scan; prompt_post_scan ;;
    1) prompt_time_window; run_deep_scan; prompt_post_scan ;;
    2) main_menu ;;
esac
