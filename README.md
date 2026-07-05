# ARP Spoofing Detection

A machine learning-based system for detecting **ARP Spoofing / Man-in-the-Middle (MITM)** behavior using **XGBoost**, Bash automation, PCAP analysis, and defensive blocking with `arptables`.

This project is built for a controlled lab environment. Network traffic is captured from a monitoring machine, converted from PCAP to CSV, analyzed by a trained XGBoost model, and used to identify the suspicious MAC address that may be performing ARP spoofing.

> **Educational and defensive use only.** Run this project only in a network environment that you own or have explicit permission to test.

---

## 1. Overview

ARP spoofing is a local network attack technique where an attacker sends falsified ARP messages to associate their MAC address with the IP address of another host. This can allow traffic interception, traffic manipulation, or network disruption.

This project focuses on the defensive detection workflow:

- Capture network traffic as PCAP files.
- Convert PCAP files into CSV format.
- Extract ARP-related traffic features.
- Run an XGBoost-based detection model.
- Identify the most suspicious source MAC address.
- Generate an `arptables` command to help block traffic from the suspected MAC address.

---

## 2. Lab Architecture

The lab scenario uses four main machines:

| Machine | Role | Example IP |
|---|---|---|
| Attacker | Generates ARP spoofing traffic in the lab environment | `192.168.15.40` |
| Snort IPS | Monitors traffic and detects abnormal IP-MAC mapping | `192.168.15.10` |
| Victim / Client | Protected client machine | `192.168.15.101` |
| SOC101 Analysis Server | Receives PCAP files and runs the AI detection script | `192.168.15.30` |

General workflow:

```text
Attacker
   |
   | ARP spoofing traffic
   v
Snort IPS / Monitoring Machine
   |
   | Captured PCAP files
   v
SOC101 Analysis Server
   |
   | Bash Script + XGBoost Model
   v
Suspicious MAC address
   |
   | Defensive action
   v
arptables blocking rule
```

---

## 3. Features

- **Machine Learning Detection**  
  Uses an XGBoost classifier to detect suspicious ARP spoofing patterns.

- **PCAP to CSV Automation**  
  Uses `tshark` to convert captured PCAP traffic into CSV format.

- **ARP Traffic Feature Extraction**  
  Extracts packet information such as source, destination, protocol, packet length, and packet details.

- **Top Attacker Identification**  
  Reads the model result and extracts the most suspicious MAC address from the `TOP ATTACKER` section.

- **Defensive Blocking Recommendation**  
  Generates an `arptables` command that can be applied on the Victim machine to drop packets from the suspected attacker MAC address.

- **Portable User Path Handling**  
  The Bash script detects the current Linux username and home directory instead of relying on a hard-coded `/home/<username>` path.

---

## 4. Project Structure

```text
Arp-Spoofing_Detection/
├── Dataset/
│   ├── Spoofing_Dataset.csv      # Training dataset
│   └── Spoofing_Test.csv         # Testing dataset
│
├── Model/
│   ├── feature_cols.pkl          # Saved feature column list
│   ├── label_map.pkl             # Saved label mapping file
│   └── xgb_model.json            # Trained XGBoost model
│
├── ARP_detection.sh              # Bash script for PCAP parsing and detection automation
├── README.md                     # Project documentation
├── XGBoost_MITM_ARP.py           # Main Python detection script
├── analysis.py                   # Additional analysis / testing script
├── requirements.txt              # Python dependencies
├── xgboost-arp.ipynb             # Notebook for model training and experiments
└── xgboost-arp_v2.ipynb          # Updated notebook version
```

> **Important:** Linux paths are case-sensitive. Keep `Dataset/`, `Model/`, `ARP_detection.sh`, and `XGBoost_MITM_ARP.py` exactly as written.

---

## 5. Requirements

### System packages

Install the required Linux tools:

```bash
sudo apt update
sudo apt install -y tshark tcpdump arptables python3 python3-pip
```

Optional, if Snort is used as the monitoring component:

```bash
sudo apt install -y snort
```

### Python packages

Install the required Python libraries:

```bash
pip3 install -r requirements.txt
```

Typical dependencies include:

```text
xgboost
pandas
numpy
scikit-learn
joblib
```

If you use the notebooks for training or experimentation, you may also need:

```text
jupyter
matplotlib
```

---

## 6. Installation

The Bash script is designed to work with the following project path:

```text
~/AI-Detection/Arp-Spoofing_Detection
```

Clone the repository into that location:

```bash
mkdir -p ~/AI-Detection
git clone https://github.com/HouseNight/Arp-Spoofing_Detection.git ~/AI-Detection/Arp-Spoofing_Detection
cd ~/AI-Detection/Arp-Spoofing_Detection
```

Install Python dependencies:

```bash
pip3 install -r requirements.txt
```

Make the detection script executable:

```bash
chmod +x ARP_detection.sh
```

If you place the repository in another directory, update the `PY_DIR` and `PY_SCRIPT` variables inside `ARP_detection.sh`.

---

## 7. Preparing PCAP Files

The detection script expects captured PCAP files to be stored in:

```text
~/backup/
```

Create the backup directory if it does not exist:

```bash
mkdir -p ~/backup
```

Example PCAP file path:

```text
~/backup/traffic.pcap0
```

If the PCAP files are stored on the Snort machine, copy them to the SOC101 Analysis Server:

```bash
scp <snort_user>@192.168.15.10:/home/<snort_user>/logfile/* ~/backup/
```

Replace `<snort_user>` with the actual username on the Snort machine.

---

## 8. Running the Detection Script

Run the script from the project directory:

```bash
cd ~/AI-Detection/Arp-Spoofing_Detection
./ARP_detection.sh traffic.pcap0
```

The script will:

1. Read the PCAP file from `~/backup/`.
2. Convert the PCAP file to CSV using `tshark`.
3. Save the generated CSV file to `~/Solution_ARP/`.
4. Run the Python XGBoost detection script.
5. Save the result text file to `~/Solution_ARP/`.
6. Extract the suspected attacker MAC address.
7. Print an `arptables` blocking command.

Example output:

```text
=====================================
User  : user
Home  : /home/user
=====================================
1. Parse PCAP -> CSV
Input : /home/user/backup/traffic.pcap0
Output: /home/user/Solution_ARP/traffic_pcap0.csv
=====================================

Đã tạo CSV: /home/user/Solution_ARP/traffic_pcap0.csv

=====================================
2. Chạy model Python
=====================================

Đã tạo result: /home/user/Solution_ARP/traffic_pcap0_result.txt

=====================================
3. Đọc TOP ATTACKER
=====================================

Phát hiện TOP ATTACKER MAC: 00:0c:29:25:79:5d

YÊU CẦU GIÁM SÁT VIÊN THỰC HIỆN LỆNH SAU TRÊN MÁY VICTIM:
sudo arptables -A INPUT --source-mac 00:0c:29:25:79:5d -j DROP
```

Generated output files:

| Output | Location |
|---|---|
| Parsed CSV file | `~/Solution_ARP/<pcap_name>.csv` |
| Detection result file | `~/Solution_ARP/<pcap_name>_result.txt` |

---

## 9. Defensive Blocking

After the script identifies a suspicious MAC address, apply the generated command on the Victim machine:

```bash
sudo arptables -A INPUT --source-mac <ATTACKER_MAC> -j DROP
```

Example:

```bash
sudo arptables -A INPUT --source-mac 00:0c:29:25:79:5d -j DROP
```

View current `arptables` rules:

```bash
sudo arptables -L
```

Remove all current `arptables` rules:

```bash
sudo arptables -F
```

---

## 10. Python Model Usage

The main Python detection script can also be executed manually with a generated CSV file:

```bash
python3 XGBoost_MITM_ARP.py ~/Solution_ARP/traffic_pcap0.csv
```

Expected behavior:

- Load the CSV traffic data.
- Build ARP spoofing-related features.
- Load the saved XGBoost model from the `Model/` directory.
- Run prediction on the input traffic.
- Print prediction statistics.
- Print the `TOP ATTACKER (ARP REPLY SPAM)` section.
- Save or display detection results.

---

## 11. Model Details

| Item | Description |
|---|---|
| Algorithm | XGBoost Classifier |
| Task | Binary classification |
| Label 0 | Benign / normal traffic |
| Label 1 | Malicious / ARP spoofing traffic |
| Main model file | `Model/xgb_model.json` |
| Feature list | `Model/feature_cols.pkl` |
| Label mapping | `Model/label_map.pkl` |
| Important feature | `arp_spoof_pattern` |
| Output | Prediction result, prediction index, prediction probability, suspicious MAC statistics |

The model is designed to detect suspicious ARP traffic patterns, especially abnormal ARP Reply behavior and duplicate IP-MAC mapping patterns.

---

## 12. Dataset

The dataset files are stored in the `Dataset/` directory:

```text
Dataset/
├── Spoofing_Dataset.csv
└── Spoofing_Test.csv
```

The dataset contains traffic records used for training and testing the ARP spoofing detection model.

Label meaning:

| Label | Meaning |
|---|---|
| `0` | Benign / normal traffic |
| `1` | Malicious / ARP spoofing traffic |

---

## 13. Example Result

Example `TOP ATTACKER` section:

```text
=== TOP ATTACKER (ARP REPLY SPAM) ===
Source
00:0c:29:25:79:5d    2
Name: count, dtype: int64
```

In this example, the suspected attacker MAC address is:

```text
00:0c:29:25:79:5d
```

The Bash script automatically extracts this MAC address and prints the corresponding blocking command.

---

## 14. Notes on Snort Monitoring

Snort can be configured to detect ARP spoofing by monitoring abnormal IP-MAC mapping changes.

Example Snort inline execution format:

```bash
sudo snort -Q --daq afpacket -i <internal_interface>:<external_interface> -A console -c /etc/snort/snort.conf
```

Example traffic capture command:

```bash
sudo tcpdump -i <interface> -w traffic.pcap -C 100 -W 10
```

Where:

- `-C 100`: creates a new file when the current PCAP reaches 100 MB.
- `-W 10`: keeps up to 10 capture files.

---

## 15. Troubleshooting

### PCAP file not found

Make sure the PCAP file exists in `~/backup/`:

```bash
ls -l ~/backup/
```

### Permission denied when running the script

Grant execute permission:

```bash
chmod +x ARP_detection.sh
```

### `tshark: command not found`

Install `tshark`:

```bash
sudo apt install -y tshark
```

### No MAC address found in `TOP ATTACKER`

Check the generated result file:

```bash
cat ~/Solution_ARP/traffic_pcap0_result.txt
```

Possible causes:

- The PCAP file does not contain enough ARP traffic.
- The model did not classify any traffic as suspicious.
- The output format of `XGBoost_MITM_ARP.py` was changed.
- The `TOP ATTACKER (ARP REPLY SPAM)` section is missing.

---

## 16. Limitations

This project is suitable for lab-scale detection and demonstration. It has several limitations:

- Detection is not fully real-time because PCAP files are collected first and analyzed later.
- Model accuracy may change in larger or more complex networks.
- False positives and false negatives may occur.
- If the attacker frequently changes MAC addresses, blocking rules must be updated.
- The model may need additional training data to generalize well across different environments.

---

## 17. Security and Legal Notice

This repository is intended for:

- Cybersecurity learning.
- Defensive network monitoring.
- Lab-based IDS/IPS testing.
- Machine learning experimentation on packet traffic.

Do not use this project to attack, intercept, or disrupt networks that you do not own or do not have explicit permission to test.

---

## 18. Author

**HouseNight**

GitHub: `https://github.com/HouseNight`

---

