import pandas as pd

print("Loading UNSW-NB15 training set...")
df = pd.read_csv('datasets/unsw-nb15/UNSW_NB15_training-set.csv')

dos_sample = df[df['attack_cat'] == 'DoS'].copy()
print(f"DoS samples available: {len(dos_sample)}")

# Take them all since it is only 4089, under 10000
dos_sample['label'] = 'DDoS'  # gabung sebagai "DDoS" family (DoS+DDoS serupa konsep)

dos_sample.to_csv('datasets/unsw_extracted.csv', index=False)
print(f"\nSaved: datasets/unsw_extracted.csv ({len(dos_sample)} rows)")
print(dos_sample['label'].value_counts())

