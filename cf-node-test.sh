#!/bin/bash
# ============================================================================
# CLOUDFLARE EDGE NODE CHECKER - SmartDist Test Tool
# Mirip judge.sh - menampilkan IP, 2x ping, dan lokasi node Cloudflare
#
# Usage:
#   ./cf-node-test.sh                          # Test 33 domain bawaan
#   ./cf-node-test.sh domain1.com domain2.com  # Test domain custom saja
#   ./cf-node-test.sh --all domain1.com        # Test bawaan + custom
#   ./cf-node-test.sh --dns 192.168.108.6      # Ganti DNS server
#   ./cf-node-test.sh --help                   # Tampilkan bantuan
# ============================================================================

# -- Default config --
DNS_SERVER="127.0.0.1"
CURL_TIMEOUT=5

# -- Warna --
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# -- 33 Domain bawaan Cloudflare (dari judge.sh) --
BUILTIN_DOMAINS="cdnjs.com
cdt.org
cloudeereviews.com
cloudflare-test.judge.sh
cloudflare-test-target.judge.sh
corporateclash.net
d3js.org
domjh.com
domjh.net
firing.it
getbootstrap.com
git-scm.com
html5boilerplate.com
i.gyazo.com
js.org
judge2020.com
judge2020.me
manfredi.io
medium.com
nodejs.org
quizlet.com
sontusdatos.org
unpkg.com
www.amnestyusa.org
www.artstation.com
www.codeguard.com
www.counterextremism.com
www.digitalocean.com
www.findlaw.com
www.loc.gov
www.ndi.org
www.opentech.fund
www.shoutmeloud.com
www.techagainstterrorism.org
www.thetrevorproject.org
www.zendesk.com"

# -- Help --
show_help() {
    echo -e "${BOLD}${CYAN}Cloudflare Edge Node Checker${NC} - SmartDist Test Tool"
    echo ""
    echo -e "${BOLD}Usage:${NC}"
    echo "  $(basename "$0") [options] [domain ...]"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  --dns <ip>    Set DNS server (default: 127.0.0.1)"
    echo "  --all         Gunakan domain bawaan + domain custom"
    echo "  --builtin     Gunakan domain bawaan saja (default jika tanpa argumen)"
    echo "  --help        Tampilkan bantuan ini"
    echo ""
    echo -e "${BOLD}Contoh:${NC}"
    echo "  $(basename "$0")                                    # 36 domain bawaan"
    echo "  $(basename "$0") --dns 192.168.108.6                # bawaan via DnsDist"
    echo "  $(basename "$0") --dns 192.168.108.6 example.com    # custom saja"
    echo "  $(basename "$0") --dns 192.168.108.6 --all my.com   # bawaan + custom"
    echo ""
    exit 0
}

# -- Parse argumen --
CUSTOM_DOMAINS=()
USE_BUILTIN=false
HAS_CUSTOM=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dns)
            DNS_SERVER="$2"
            shift 2
            ;;
        --all)
            USE_BUILTIN=true
            shift
            ;;
        --builtin)
            USE_BUILTIN=true
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            CUSTOM_DOMAINS+=("$1")
            HAS_CUSTOM=true
            shift
            ;;
    esac
done

# Jika tidak ada custom domain dan tidak ada flag, pakai bawaan
if [[ "$HAS_CUSTOM" == false ]]; then
    USE_BUILTIN=true
fi

# -- Bangun daftar domain final --
FINAL_DOMAINS=""
if [[ "$USE_BUILTIN" == true ]]; then
    FINAL_DOMAINS="$BUILTIN_DOMAINS"
fi
for d in "${CUSTOM_DOMAINS[@]}"; do
    FINAL_DOMAINS="${FINAL_DOMAINS}
${d}"
done
# Hapus baris kosong
FINAL_DOMAINS=$(echo "$FINAL_DOMAINS" | sed '/^[[:space:]]*$/d')

DOMAIN_COUNT=$(echo "$FINAL_DOMAINS" | wc -l)

# -- Header --
echo ""
echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║               CLOUDFLARE EDGE NODE CHECKER - SmartDist Test Tool                   ║${NC}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════════════════════════╝${NC}"
echo -e " ${DIM}DNS Server :${NC} ${BOLD}${DNS_SERVER}${NC}"
echo -e " ${DIM}Domains    :${NC} ${BOLD}${DOMAIN_COUNT}${NC} ${DIM}(builtin: ${USE_BUILTIN}, custom: ${#CUSTOM_DOMAINS[@]})${NC}"
echo -e " ${DIM}Timestamp  :${NC} ${BOLD}$(date '+%Y-%m-%d %H:%M:%S %Z')${NC}"
echo ""

# -- Koleksi node unik --
declare -A node_count

# -- Tabel header --
printf "${BOLD}%-38s %-18s %-10s %-10s %-8s${NC}\n" \
    "DOMAIN" "IP" "PING #1" "PING #2" "NODE"
printf "%-38s %-18s %-10s %-10s %-8s\n" \
    "$(printf '%.0s─' $(seq 1 38))" \
    "$(printf '%.0s─' $(seq 1 18))" \
    "$(printf '%.0s─' $(seq 1 10))" \
    "$(printf '%.0s─' $(seq 1 10))" \
    "$(printf '%.0s─' $(seq 1 8))"

total=0

# -- Fungsi: warnai ping --
color_ping() {
    local ms="$1"
    if [[ "$ms" == "-" ]]; then echo -e "${DIM}-${NC}"; return; fi
    local num=${ms%.*}
    if [[ "$num" -lt 30 ]]; then echo -e "${GREEN}${ms}ms${NC}"
    elif [[ "$num" -lt 100 ]]; then echo -e "${YELLOW}${ms}ms${NC}"
    else echo -e "${RED}${ms}ms${NC}"; fi
}

# -- Fungsi: satu ping (auto IPv4/IPv6) --
do_ping() {
    local ip="$1"
    local result
    if [[ "$ip" == *:* ]]; then
        result=$(ping -6 -c 1 -W 2 "$ip" 2>/dev/null | sed -n 's|.*time=\([0-9.]*\).*|\1|p')
    else
        result=$(ping -c 1 -W 2 "$ip" 2>/dev/null | sed -n 's|.*time=\([0-9.]*\).*|\1|p')
    fi
    echo "${result:--}"
}

# -- Main loop --
while IFS= read -r domain; do
    domain=$(echo "$domain" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [[ -z "$domain" || "$domain" == \#* ]] && continue
    total=$((total + 1))

    # 1. Resolve: prioritas IPv6 (AAAA), fallback IPv4 (A)
    resolved_v6=$(dig +short +time=3 @"$DNS_SERVER" "$domain" AAAA 2>/dev/null | grep -E '^[0-9a-f]+:' | head -1)
    resolved_v4=$(dig +short +time=3 @"$DNS_SERVER" "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1)

    resolved=""
    ip_ver=""

    # Coba IPv6 dulu: resolve + bisa di-ping?
    if [[ -n "$resolved_v6" ]]; then
        test_ping=$(ping -6 -c 1 -W 2 "$resolved_v6" 2>/dev/null | sed -n 's|.*time=\([0-9.]*\).*|\1|p')
        if [[ -n "$test_ping" ]]; then
            resolved="$resolved_v6"
            ip_ver="6"
        fi
    fi

    # Fallback ke IPv4 jika IPv6 tidak bisa di-ping
    if [[ -z "$resolved" && -n "$resolved_v4" ]]; then
        resolved="$resolved_v4"
        ip_ver="4"
    fi

    # Jika tidak resolve sama sekali
    if [[ -z "$resolved" ]]; then
        printf "%-38s ${RED}%-18s${NC} %-10s %-10s %-8s\n" \
            "$domain" "NO RESOLVE" "-" "-" "-"
        continue
    fi

    # Truncate IP panjang untuk display
    display_ip="$resolved"
    if [[ ${#display_ip} -gt 18 ]]; then
        display_ip="${display_ip:0:15}..."
    fi

    # 2. CF-Ray header
    cf_node="-"
    if [[ "$ip_ver" == "6" ]]; then
        headers=$(curl -sI --max-time "$CURL_TIMEOUT" \
            --resolve "${domain}:443:[${resolved}]" \
            -6 "https://${domain}/" 2>/dev/null)
    else
        headers=$(curl -sI --max-time "$CURL_TIMEOUT" \
            --resolve "${domain}:443:${resolved}" \
            "https://${domain}/" 2>/dev/null)
    fi
    if [[ -n "$headers" ]]; then
        cf_ray=$(echo "$headers" | grep -i "^cf-ray:" | head -1 | tr -d '\r')
        if [[ -n "$cf_ray" ]]; then
            cf_node=$(echo "$cf_ray" | sed -n 's/.*-\([A-Za-z]\{3,4\}\)$/\1/p')
            [[ -z "$cf_node" ]] && cf_node="-"
        fi
    fi

    # 3. Dua kali ping
    ping1=$(do_ping "$resolved")
    ping2=$(do_ping "$resolved")

    # 4. Format & print
    p1=$(color_ping "$ping1")
    p2=$(color_ping "$ping2")

    if [[ "$cf_node" != "-" ]]; then
        nd="${CYAN}${BOLD}${cf_node}${NC}"
        node_count["$cf_node"]=$(( ${node_count["$cf_node"]:-0} + 1 ))
    else
        nd="${DIM}-${NC}"
    fi

    printf "%-38s %-18s %-20b %-20b %-18b\n" \
        "$domain" "$display_ip" "$p1" "$p2" "$nd"

done <<< "$FINAL_DOMAINS"

# -- Summary --
echo ""
echo -e "$(printf '%.0s─' $(seq 1 84))"
echo -e "${BOLD}Total:${NC} ${total} domains tested"
echo ""

if [[ ${#node_count[@]} -gt 0 ]]; then
    echo -e "${BOLD}${CYAN}Cloudflare Nodes Detected:${NC}"
    for node in $(echo "${!node_count[@]}" | tr ' ' '\n' | sort); do
        echo -e "  ${CYAN}${BOLD}${node}${NC} — ${node_count[$node]} domain(s)"
    done
    echo ""
fi
