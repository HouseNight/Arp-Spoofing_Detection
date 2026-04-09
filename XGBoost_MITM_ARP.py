from analysis import analyze_attack
import xgboost as xgb
import pickle
import pandas as pd
import numpy as np
import re
import sys
import os

def build_spoofing_features(df):
    df = df.copy()

    # =========================================================
    # 0. CHUẨN HÓA CỘT
    # =========================================================
    for col in ['Protocol', 'Info', 'Source', 'Destination']:
        if col not in df.columns:
            df[col] = ''
        df[col] = df[col].astype(str).fillna('')

    info_lower = df['Info'].str.lower()
    proto_lower = df['Protocol'].str.lower()

    # =========================================================
    # 1. FEATURE CƠ BẢN
    # =========================================================
    df['Length'] = pd.to_numeric(df.get('Length', 0), errors='coerce').fillna(0)

    df['is_arp'] = proto_lower.str.contains('arp', regex=False).astype(int)
    df['is_tcp'] = proto_lower.str.contains('tcp', regex=False).astype(int)
    df['is_udp'] = proto_lower.str.contains('udp', regex=False).astype(int)
    df['is_icmp'] = proto_lower.str.contains('icmp', regex=False).astype(int)

    # =========================================================
    # 2. FEATURE TỪ INFO (vectorized - nhanh)
    # =========================================================
    df['is_request'] = info_lower.str.contains('who has', regex=False).astype(int)
    df['is_reply'] = info_lower.str.contains('is at', regex=False).astype(int)
    df['has_duplicate_ip'] = info_lower.str.contains('duplicate use of', regex=False).astype(int)
    df['has_reply_word'] = info_lower.str.contains(r'\breply\b').astype(int)
    df['has_request_word'] = info_lower.str.contains(r'\brequest\b').astype(int)
    df['has_broadcast'] = info_lower.str.contains('broadcast', regex=False).astype(int)
    df['has_unicast'] = info_lower.str.contains('unicast', regex=False).astype(int)
    df['has_tell'] = info_lower.str.contains('tell', regex=False).astype(int)

    # Pattern ARP spoof
    df['arp_spoof_pattern'] = (
        (df['is_arp'] == 1) &
        ((df['is_reply'] == 1) | (df['has_duplicate_ip'] == 1))
    ).astype(int)

    # =========================================================
    # 3. TRÍCH IP (FAST - không dùng apply)
    # =========================================================
    ip_pattern = r'(\d{1,3}(?:\.\d{1,3}){3})'
    extracted_ips = df['Info'].str.findall(ip_pattern)

    df['ip_count_in_info'] = extracted_ips.str.len().fillna(0)

    # Không encode IP trực tiếp (tránh bug deploy)
    df['has_multiple_ips'] = (df['ip_count_in_info'] > 1).astype(int)

    # =========================================================
    # 4. CHANGE FEATURE (fix logic)
    # =========================================================
    df['source_changed'] = (df['Source'] != df['Source'].shift()).astype(int)
    df['destination_changed'] = (df['Destination'] != df['Destination'].shift()).astype(int)

    # =========================================================
    # 5. FREQUENCY FEATURE
    # =========================================================
    src_counts = df['Source'].value_counts()
    dst_counts = df['Destination'].value_counts()

    df['source_freq'] = df['Source'].map(src_counts).fillna(0)
    df['destination_freq'] = df['Destination'].map(dst_counts).fillna(0)

    # =========================================================
    # 6. TIME FEATURE (nếu có)
    # =========================================================
    if 'Time' in df.columns:
        df['Time'] = pd.to_numeric(df['Time'], errors='coerce')
        df['time_diff'] = df['Time'].diff().fillna(0)
    else:
        df['time_diff'] = 0

    # =========================================================
    # 7. CHỌN FEATURE CUỐI
    # =========================================================
    feature_cols = [
        'Length',
        'is_arp', 'is_tcp', 'is_udp', 'is_icmp',
        'is_request', 'is_reply',
        'has_duplicate_ip', 'has_reply_word', 'has_request_word',
        'has_broadcast', 'has_unicast', 'has_tell',
        'arp_spoof_pattern',
        'ip_count_in_info', 'has_multiple_ips',
        'source_changed', 'destination_changed',
        'source_freq', 'destination_freq',
        'time_diff'
    ]

    feature_df = df[feature_cols].copy()
    feature_df = feature_df.replace([np.inf, -np.inf], np.nan).fillna(0)

    return feature_df, feature_cols



# Load model
model = xgb.XGBClassifier()
model.load_model("xgb_model.json")

# Load label map
label_to_index = pickle.load(open("label_map.pkl", "rb"))
index_to_label = {v: k for k, v in label_to_index.items()}

# Load feature columns
feature_cols = pickle.load(open("feature_cols.pkl", "rb"))

# =========================================================
# LẤY FILE INPUT TỪ argv
# =========================================================
if len(sys.argv) < 2:
    print("Usage: python testing.py <input_file.csv>")
    sys.exit(1)

input_file = sys.argv[1]

df_test = pd.read_csv(input_file)

# Load File to processing feature

X_test_df, _ = build_spoofing_features(df_test)

# Đảm bảo đúng thứ tự cột như lúc train
X_test_df = X_test_df[feature_cols]

y_pred = model.predict(X_test_df.values)

# Decode label


pred_labels = [index_to_label[i] for i in y_pred]

df_test['Prediction'] = pred_labels

print(df_test[['Prediction']].head())

# =========================================================
# TẠO TÊN FILE OUTPUT
# =========================================================
base_name = os.path.splitext(input_file)[0]
output_file = base_name + "_result.csv"

df_test.to_csv(output_file, index=False)

print(f"Saved to: {output_file}")

# Hoàn thành
print("==============",end="\n")
print("Done processing Tagging File", end="\n")
print("==============",end="\n")

# analysis
analyze_attack(output_file)
