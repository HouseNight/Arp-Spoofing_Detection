from analysis import analyze_attack
import xgboost as xgb
import pickle
import pandas as pd
import numpy as np
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
        df[col] = df[col].fillna('').astype(str)

    info_lower = df['Info'].str.lower()
    proto_lower = df['Protocol'].str.lower()

    # =========================================================
    # 1. FEATURE CƠ BẢN
    # =========================================================
    if 'Length' in df.columns:
        df['Length'] = pd.to_numeric(df['Length'], errors='coerce').fillna(0)
    else:
        df['Length'] = 0

    df['is_arp'] = proto_lower.str.contains('arp', regex=False).astype(int)
    df['is_tcp'] = proto_lower.str.contains('tcp', regex=False).astype(int)
    df['is_udp'] = proto_lower.str.contains('udp', regex=False).astype(int)
    df['is_icmp'] = proto_lower.str.contains('icmp', regex=False).astype(int)

    # =========================================================
    # 2. FEATURE TỪ INFO
    # =========================================================
    df['is_request'] = info_lower.str.contains('who has', regex=False).astype(int)
    df['is_reply'] = info_lower.str.contains('is at', regex=False).astype(int)
    df['has_duplicate_ip'] = info_lower.str.contains('duplicate use of', regex=False).astype(int)
    df['has_reply_word'] = info_lower.str.contains(r'\breply\b', regex=True).astype(int)
    df['has_request_word'] = info_lower.str.contains(r'\brequest\b', regex=True).astype(int)
    df['has_broadcast'] = info_lower.str.contains('broadcast', regex=False).astype(int)
    df['has_unicast'] = info_lower.str.contains('unicast', regex=False).astype(int)
    df['has_tell'] = info_lower.str.contains('tell', regex=False).astype(int)

    df['arp_spoof_pattern'] = (
        (df['is_arp'] == 1) &
        ((df['is_reply'] == 1) | (df['has_duplicate_ip'] == 1))
    ).astype(int)

    # =========================================================
    # 3. TRÍCH IP
    # =========================================================
    ip_pattern = r'(\d{1,3}(?:\.\d{1,3}){3})'
    extracted_ips = df['Info'].str.findall(ip_pattern)

    df['ip_count_in_info'] = extracted_ips.str.len().fillna(0)
    df['has_multiple_ips'] = (df['ip_count_in_info'] > 1).astype(int)

    # =========================================================
    # 4. CHANGE FEATURE
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
    # 6. TIME FEATURE
    # =========================================================
    if 'Time' in df.columns:
        df['Time'] = pd.to_numeric(df['Time'], errors='coerce')
        df['time_diff'] = df['Time'].diff().fillna(0)
    else:
        df['time_diff'] = 0

    # =========================================================
    # 7. FEATURE CUỐI
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

    # ép toàn bộ về numeric để predict ổn định
    feature_df = feature_df.apply(pd.to_numeric, errors='coerce').fillna(0)

    return feature_df, feature_cols


def check_required_files():
    required_files = ["xgb_model.json", "label_map.pkl", "feature_cols.pkl"]
    missing = [f for f in required_files if not os.path.exists(f)]
    if missing:
        print("Thiếu file cần thiết:", ", ".join(missing))
        sys.exit(1)


def main():
    # =========================================================
    # CHECK INPUT
    # =========================================================
    if len(sys.argv) < 2:
        print("Usage: python testing.py <input_file.csv>")
        sys.exit(1)

    input_file = sys.argv[1]

    if not os.path.exists(input_file):
        print(f"Không tìm thấy file input: {input_file}")
        sys.exit(1)

    check_required_files()

    # =========================================================
    # LOAD MODEL + META
    # =========================================================
    model = xgb.XGBClassifier()
    model.load_model("xgb_model.json")

    with open("label_map.pkl", "rb") as f:
        label_to_index = pickle.load(f)

    with open("feature_cols.pkl", "rb") as f:
        trained_feature_cols = pickle.load(f)

    index_to_label = {int(v): k for k, v in label_to_index.items()}

    # =========================================================
    # LOAD TEST DATA
    # =========================================================
    df_test = pd.read_csv(input_file)

    print("Input shape:", df_test.shape)
    print("Input columns:", df_test.columns.tolist())

    # =========================================================
    # BUILD FEATURE
    # =========================================================
    X_test_df, current_feature_cols = build_spoofing_features(df_test)

    # Nếu model train dùng cột nào mà test chưa có -> thêm 0
    for col in trained_feature_cols:
        if col not in X_test_df.columns:
            X_test_df[col] = 0

    # Chỉ lấy đúng thứ tự cột lúc train
    X_test_df = X_test_df[trained_feature_cols].copy()

    # Làm sạch lần cuối
    X_test_df = X_test_df.replace([np.inf, -np.inf], np.nan).fillna(0)
    X_test_df = X_test_df.apply(pd.to_numeric, errors='coerce').fillna(0)

    print("Feature shape:", X_test_df.shape)

    # =========================================================
    # PREDICT
    # =========================================================
    y_pred = model.predict(X_test_df.values)

    # Nếu model hỗ trợ predict_proba thì lưu luôn
    y_pred_prob = None
    try:
        y_pred_prob = model.predict_proba(X_test_df.values)[:, 1]
    except Exception:
        pass

    pred_labels = [index_to_label.get(int(i), str(int(i))) for i in y_pred]

    df_test['Prediction'] = pred_labels
    df_test['Prediction_Index'] = [int(i) for i in y_pred]

    if y_pred_prob is not None:
        df_test['Prediction_Prob'] = y_pred_prob

    print(df_test[['Prediction']].head())

    # =========================================================
    # TẠO FILE OUTPUT
    # =========================================================
    base_name = os.path.splitext(input_file)[0]
    output_file = base_name + "_result.csv"

    df_test.to_csv(output_file, index=False)

    print(f"Saved to: {output_file}")
    print("==============")
    print("Done processing Tagging File")
    print("==============")

    # =========================================================
    # ANALYSIS
    # =========================================================
    try:
        analyze_attack(output_file)
    except Exception as e:
        print(f"analyze_attack lỗi nhưng file predict đã lưu thành công: {e}")


if __name__ == "__main__":
    main()
