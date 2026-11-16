import pandas as pd

print("Loading CICIDS2017 Tuesday (Brute Force)...")
df = pd.read_csv('datasets/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv')

# Note: column names have a leading space, e.g. ' Label' not 'Label'
# Clean the column names first so they are easier to use
df.columns = df.columns.str.strip()

brute_force = df[df['Label'].isin(['FTP-Patator', 'SSH-Patator'])].copy()
print(f"Brute Force samples available: {len(brute_force)}")

brute_force['label'] = 'Brute Force'

brute_force.to_csv('datasets/cicids_extracted.csv', index=False)
print(f"\nSaved: datasets/cicids_extracted.csv ({len(brute_force)} rows)")
print(brute_force['label'].value_counts())
print("\nBreakdown asal:")
print(brute_force['Label'].value_counts())
