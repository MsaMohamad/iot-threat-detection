import pandas as pd
import numpy as np

def safe_div(a, b):
    """Avoid divide by zero - use +1 as a small buffer"""
    return a / (b + 1)

# ========================================
# 1. BOT-IOT (DDoS + Port Scan)
# ========================================
print("Processing Bot-IoT...")
bi = pd.read_csv('datasets/bot_iot_extracted.csv')

bi_out = pd.DataFrame()
bi_out['duration_sec'] = bi['dur']
bi_out['total_bytes'] = bi['sbytes'] + bi['dbytes']
bi_out['total_pkts'] = bi['spkts'] + bi['dpkts']
bi_out['bytes_per_sec'] = safe_div(bi_out['total_bytes'], bi_out['duration_sec'])
bi_out['pkts_per_sec'] = safe_div(bi_out['total_pkts'], bi_out['duration_sec'])
bi_out['avg_pkt_size'] = safe_div(bi_out['total_bytes'], bi_out['total_pkts'])
bi_out['fwd_bwd_byte_ratio'] = safe_div(bi['sbytes'], bi['dbytes'])
bi_out['fwd_bwd_pkt_ratio'] = safe_div(bi['spkts'], bi['dpkts'])
bi_out['label'] = bi['label']
bi_out['source'] = 'bot-iot'

print(f"  -> {len(bi_out)} rows processed")

# ========================================
# 2. UNSW-NB15 (DDoS)
# ========================================
print("Processing UNSW-NB15...")
un = pd.read_csv('datasets/unsw_extracted.csv')

un_out = pd.DataFrame()
un_out['duration_sec'] = un['dur']
un_out['total_bytes'] = un['sbytes'] + un['dbytes']
un_out['total_pkts'] = un['spkts'] + un['dpkts']
un_out['bytes_per_sec'] = safe_div(un_out['total_bytes'], un_out['duration_sec'])
un_out['pkts_per_sec'] = safe_div(un_out['total_pkts'], un_out['duration_sec'])
un_out['avg_pkt_size'] = safe_div(un_out['total_bytes'], un_out['total_pkts'])
un_out['fwd_bwd_byte_ratio'] = safe_div(un['sbytes'], un['dbytes'])
un_out['fwd_bwd_pkt_ratio'] = safe_div(un['spkts'], un['dpkts'])
un_out['label'] = un['label']
un_out['source'] = 'unsw-nb15'

print(f"  -> {len(un_out)} rows processed")

# ========================================
# 3. CICIDS2017 (Brute Force) - unit mikrosaat!
# ========================================
print("Processing CICIDS2017 Brute Force...")
ci = pd.read_csv('datasets/cicids_extracted.csv')
ci.columns = ci.columns.str.strip()

ci_out = pd.DataFrame()
ci_out['duration_sec'] = ci['Flow Duration'] / 1_000_000
ci_out['total_bytes'] = ci['Total Length of Fwd Packets'] + ci['Total Length of Bwd Packets']
ci_out['total_pkts'] = ci['Total Fwd Packets'] + ci['Total Backward Packets']
ci_out['bytes_per_sec'] = safe_div(ci_out['total_bytes'], ci_out['duration_sec'])
ci_out['pkts_per_sec'] = safe_div(ci_out['total_pkts'], ci_out['duration_sec'])
ci_out['avg_pkt_size'] = safe_div(ci_out['total_bytes'], ci_out['total_pkts'])
ci_out['fwd_bwd_byte_ratio'] = safe_div(ci['Total Length of Fwd Packets'], ci['Total Length of Bwd Packets'])
ci_out['fwd_bwd_pkt_ratio'] = safe_div(ci['Total Fwd Packets'], ci['Total Backward Packets'])
ci_out['label'] = ci['label']
ci_out['source'] = 'cicids2017'

print(f"  -> {len(ci_out)} rows processed")

# ========================================
# 4. NORMAL (from CICIDS2017 BENIGN)
# ========================================
print("Processing Normal traffic...")
nm = pd.read_csv('datasets/normal_extracted.csv')
nm.columns = nm.columns.str.strip()

nm_out = pd.DataFrame()
nm_out['duration_sec'] = nm['Flow Duration'] / 1_000_000
nm_out['total_bytes'] = nm['Total Length of Fwd Packets'] + nm['Total Length of Bwd Packets']
nm_out['total_pkts'] = nm['Total Fwd Packets'] + nm['Total Backward Packets']
nm_out['bytes_per_sec'] = safe_div(nm_out['total_bytes'], nm_out['duration_sec'])
nm_out['pkts_per_sec'] = safe_div(nm_out['total_pkts'], nm_out['duration_sec'])
nm_out['avg_pkt_size'] = safe_div(nm_out['total_bytes'], nm_out['total_pkts'])
nm_out['fwd_bwd_byte_ratio'] = safe_div(nm['Total Length of Fwd Packets'], nm['Total Length of Bwd Packets'])
nm_out['fwd_bwd_pkt_ratio'] = safe_div(nm['Total Fwd Packets'], nm['Total Backward Packets'])
nm_out['label'] = nm['label']
nm_out['source'] = 'cicids2017'

print(f"  -> {len(nm_out)} rows processed")

# ========================================
# COMBINE ALL
# ========================================
print("\nCombining all datasets...")
combined = pd.concat([bi_out, un_out, ci_out, nm_out], ignore_index=True)

# Cleanup: drop rows with NaN or infinity (from divide-by-zero edge cases)
before = len(combined)
combined = combined.replace([np.inf, -np.inf], np.nan)
combined = combined.dropna()
after = len(combined)
print(f"Dropped {before - after} rows with NaN/infinity values")

combined.to_csv('datasets/combined_dataset.csv', index=False)
print(f"\n✅ SAVED: datasets/combined_dataset.csv")
print(f"Total rows: {len(combined)}")
print(f"\nLabel distribution:")
print(combined['label'].value_counts())
print(f"\nSource distribution:")
print(combined['source'].value_counts())
