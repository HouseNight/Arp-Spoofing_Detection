import pandas as pd
import re

def analyze_attack(file_path):
    df = pd.read_csv(file_path)

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
    print(df_reply['Source'].value_counts().head(5))

    # =========================================================
    # 4. TRÍCH IP
    # =========================================================
    def extract_ip(text):
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', str(text))
        return match.group(1) if match else None

    df_attack = df_attack.copy()
    df_attack.loc[:, 'IP'] = df_attack['Info'].apply(extract_ip)

    # =========================================================
    # 5. ATTACKER CHÍNH
    # =========================================================
    main_attacker = attacker_counts.idxmax()
    print(f"\n🎯 MAIN ATTACKER: {main_attacker}")

    print("\n=== TOP 5 ATTACKER IP ===")
    attacker_ip_counts = (
        df_attack[df_attack['Source'] == main_attacker]['IP']
        .value_counts()
        .head(5)
    )

    for ip, count in attacker_ip_counts.items():
        print(f"{ip:<20} {count}")

    # =========================================================
    # 6. VICTIM CHÍNH
    # =========================================================
    main_victim = victim_counts.idxmax()
    print(f"\n👤 MAIN VICTIM: {main_victim}")

    print("\n=== TOP 5 VICTIM IP ===")
    victim_ip_counts = (
        df_attack[df_attack['Destination'] == main_victim]['IP']
        .value_counts()
        .head(5)
    )

    for ip, count in victim_ip_counts.items():
        print(f"{ip:<20} {count}")

    # =========================================================
    # 7. CHECK MITM
    # =========================================================
    attacker_ips = df_attack[df_attack['Source'] == main_attacker]['IP'].nunique()

    if attacker_ips > 1:
        print("\n⚠️ WARNING: Possible MITM attack (1 MAC → multiple IPs)")
    else:
        print("\n✅ No strong MITM pattern detected")