#!/bin/bash

set -u

BACKUP_DIR="/home/nohax/backup"
PY_DIR="/home/nohax/AI-Detection/Arp-Spoofing_Detection"
PY_SCRIPT="/home/nohax/AI-Detection/Arp-Spoofing_Detection/XGBoost_MITM_ARP.py"

if [ $# -ne 1 ]; then
    echo "Cách dùng: $0 <ten_file_pcap>"
    echo "Ví dụ: $0 traffic.pcap0"
    exit 1
fi

PCAP_NAME="$1"
PCAP_PATH="$BACKUP_DIR/$PCAP_NAME"

if [ ! -f "$PCAP_PATH" ]; then
    echo "Lỗi: Không tìm thấy file pcap: $PCAP_PATH"
    exit 1
fi

if [ ! -d "$PY_DIR" ]; then
    echo "Lỗi: Không tìm thấy thư mục Python: $PY_DIR"
    exit 1
fi

if [ ! -f "$PY_SCRIPT" ]; then
    echo "Lỗi: Không tìm thấy script Python: $PY_SCRIPT"
    exit 1
fi

BASE_NAME="$(basename "$PCAP_NAME")"
SAFE_NAME="${BASE_NAME//./_}"
CSV_NAME="${SAFE_NAME}.csv"
CSV_PATH="/home/nohax/Solution_ARP/$CSV_NAME"
RESULT_TXT="/home/nohax/Solution_ARP/${SAFE_NAME}_result.txt"

echo "====================================="
echo "1. Parse PCAP -> CSV"
echo "Input : $PCAP_PATH"
echo "Output: $CSV_PATH"
echo "====================================="

TMP_CSV="${CSV_PATH}.tmp"

tshark -r "$PCAP_PATH" \
-T fields \
-e frame.number \
-e frame.time_relative \
-e ip.src \
-e eth.src \
-e ip.dst \
-e eth.dst \
-e _ws.col.Protocol \
-e frame.len \
-e _ws.col.Info \
-E header=y \
-E separator=, \
-E quote=d \
> "$TMP_CSV"

awk -F',' 'BEGIN {
    OFS=","
    print "\"No.\",\"Time\",\"Source\",\"Destination\",\"Protocol\",\"Length\",\"Info\""
}
NR>1 {
    gsub(/"/, "", $0)

    src = ($3 != "" ? $3 : $4)
    dst = ($5 != "" ? $5 : $6)

    print $1, $2, src, dst, $7, $8, $9
}' "$TMP_CSV" > "$CSV_PATH"

rm -f "$TMP_CSV"
if [ ! -f "$CSV_PATH" ]; then
    echo "Lỗi: Không tạo được file CSV"
    exit 1
fi

echo "Đã tạo CSV: $CSV_PATH"
echo

echo "====================================="
echo "2. Chạy model Python"
echo "====================================="

cd "$PY_DIR" || exit 1
python3 "$PY_SCRIPT" "$CSV_PATH" > "$RESULT_TXT" 2>&1

if [ ! -f "$RESULT_TXT" ]; then
    echo "Lỗi: Không tạo được file result txt"
    exit 1
fi

echo "Đã tạo result: $RESULT_TXT"
echo

echo "====================================="
echo "3. Đọc TOP ATTACKER"
echo "====================================="

TOP_MAC=$(
awk '
/^=== TOP ATTACKER \(ARP REPLY SPAM\) ===$/ {found=1; next}
found && /^[[:space:]]*Source[[:space:]]*$/ {next}
found && /^[[:space:]]*$/ {next}
found && /^Name:/ {exit}
found {
    if (match($0, /([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/)) {
        print substr($0, RSTART, RLENGTH)
        exit
    }
}
' "$RESULT_TXT"
)

if [ -n "$TOP_MAC" ]; then
    echo "Phát hiện TOP ATTACKER MAC: $TOP_MAC"
    echo
    echo "=========================================="
    echo "YÊU CẦU GIÁM SÁT VIÊN THỰC HIỆN LỆNH SAU TRÊN MÁY VICTIM:"
    echo "=========================================="
    echo "sudo arptables -A INPUT --source-mac $TOP_MAC -j DROP"
else
    echo "Không tìm thấy MAC trong mục TOP ATTACKER."
    echo "Kiểm tra file: $RESULT_TXT"
    exit 1
fi
