import pandas as pd
import re

def normalize_vmware_mac(mac):
    if isinstance(mac, str) and mac.startswith("VMware_"):
        suffix = mac.split("_")[1]
        return "00:0C:29:" + suffix.upper()
    return mac

def analyze_attack(file_path):
    df = pd.read_csv(file_path)

    # Chuẩn hóa MAC trước
    df['Source'] = df['Source'].apply(normalize_vmware_mac)
    df['Destination'] = df['Destination'].apply(normalize_vmware_mac)

    # =========================================================
    # 1. LỌC ARP + MALICIOUS
    # =========================================================
    df_arp = df[df['Protocol'].str.lower().str.contains('arp', na=False)]
    df_attack = df_arp[df_arp['Prediction'] == 'Mallicious']

    print("Total suspicious packets:", len(df_attack))

    # =========================================================
    # 2. ATTACKER / VICTIM (MAC)
    # =========================================================
    print("\n=== ATTACKERS (MAC) ===")
    attacker_counts = df_attack['Source'].value_counts()
    print(attacker_counts.head(5))

    print("\n=== VICTIMS (MAC) ===")
    victim_counts = df_attack['Destination'].value_counts()
    print(victim_counts.head(5))

    # =========================================================
    # 3. LỌC ARP REPLY
    # =========================================================
    df_reply = df_attack[df_attack['Info'].str.contains('is at', na=False)]

    print("\n=== TOP ATTACKER (ARP REPLY SPAM) ===")
    print(df_reply['Source'].value_counts().head(1))
