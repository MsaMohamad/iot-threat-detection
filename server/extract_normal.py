import pandas as pd

print("Loading CICIDS2017 Tuesday (for Normal traffic)...")
df = pd.read_csv('datasets/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv')
df.columns = df.columns.str.strip()

normal_sample = df[df['Label'] == 'BENIGN'].sample(n=15000, random_state=42).copy()
print(f"Normal samples available: {(df['Label'] == 'BENIGN').sum()}")
print(f"Normal samples used: {len(normal_sample)}")

normal_sample['label'] = 'Normal'

normal_sample.to_csv('datasets/normal_extracted.csv', index=False)
print(f"\nSaved: datasets/normal_extracted.csv ({len(normal_sample)} rows)")
