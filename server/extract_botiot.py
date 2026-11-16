import pandas as pd

# ==== DDoS from File 3 ====
print("Loading File 3 (DDoS)...")
df3 = pd.read_csv('datasets/bot-iot/reduced_data_3.csv')
ddos_sample = df3[df3['category'] == 'DDoS'].sample(n=10000, random_state=42)
print(f"DDoS samples: {len(ddos_sample)}")

# ==== Port Scan (Reconnaissance) from File 4 ====
print("Loading File 4 (Reconnaissance/Port Scan)...")
df4 = pd.read_csv('datasets/bot-iot/reduced_data_4.csv')
portscan_sample = df4[df4['category'] == 'Reconnaissance']
print(f"Port Scan samples available: {len(portscan_sample)}")
# take them all since it is only ~91k; no need to sample further for >10k
portscan_sample = portscan_sample.sample(n=10000, random_state=42)
print(f"Port Scan samples used: {len(portscan_sample)}")

# ==== Gabung & label semula ====
ddos_sample = ddos_sample.copy()
portscan_sample = portscan_sample.copy()
ddos_sample['label'] = 'DDoS'
portscan_sample['label'] = 'Port Scan'

combined = pd.concat([ddos_sample, portscan_sample], ignore_index=True)
combined.to_csv('datasets/bot_iot_extracted.csv', index=False)
print(f"\nSaved: datasets/bot_iot_extracted.csv ({len(combined)} rows)")
print(combined['label'].value_counts())

