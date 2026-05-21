#!/bin/bash
# attack_simulation_30.sh - Run on VM3 (Attacker)
# Enhanced: Console output, progress tracking, timing, and result stats

ITER=30
TARGET_DNS="192.168.1.60"
DOMAIN="mirrortest.lab"
WORDLIST="/usr/share/seclists/DNS/subdomains-top1million-custom.txt"
LOG_DIR="$HOME/attack_logs"

# Fallback if SecLists snap not installed
if [ ! -f "$WORDLIST" ]; then
    WORDLIST="$HOME/subdomains.txt"
    echo "⚠️ Using fallback wordlist: $WORDLIST"
fi

mkdir -p "$LOG_DIR"
echo "🚀 Starting $ITER iterations of DNS enumeration against $TARGET_DNS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TOTAL_START=$(date +%s)

for i in $(seq 1 $ITER); do
    ITER_START=$(date +%s)
    PERCENT=$(( (i * 100) / ITER ))

    # Progress header
    printf "\n🔄 Iteration %d/%d [%3d%%] | Started: %s\n" "$i" "$ITER" "$PERCENT" "$(date '+%H:%M:%S')"

    # Run dnsrecon:
    # 2>&1 captures both stdout & stderr
    # tee prints to console AND saves to log file simultaneously
    dnsrecon -d "$DOMAIN" -t brt -D "$WORDLIST" -n "$TARGET_DNS" --threads 30 2>&1 | tee "$LOG_DIR/iter_$i.log"

    # Extract quick stats from the log for this iteration
    # Counts lines containing IPv4 addresses (successful A record resolutions)
    FOUND=$(grep -cE "([0-9]{1,3}\.){3}[0-9]{1,3}" "$LOG_DIR/iter_$i.log" 2>/dev/null || echo "0")
    # Counts error/timeout keywords
    ERRORS=$(grep -ic "timeout\|error\|refused\|SERVFAIL\|connection refused" "$LOG_DIR/iter_$i.log" 2>/dev/null || echo "0")

    ITER_END=$(date +%s)
    DURATION=$((ITER_END - ITER_START))

    # Iteration summary
    echo ""
    echo "✅ Iteration $i Complete | ⏱️ ${DURATION}s | 📦 Resolved: $FOUND | ⚠️ Issues: $ERRORS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Brief pause to prevent DNS server overload
    if [ $i -lt $ITER ]; then
        sleep 2
    fi
done

TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

echo ""
echo "🎉 SIMULATION COMPLETE"
echo "⏱️ Total Runtime: ${TOTAL_DURATION} seconds"
echo "📂 All logs saved to: $LOG_DIR"
echo "📊 Monitor real-time decoy hits on VM2: tail -f /opt/dnsmirror/attacks.json"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"