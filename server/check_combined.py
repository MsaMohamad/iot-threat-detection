import pandas as pd

df = pd.read_csv('datasets/combined_dataset.csv')

print("=" * 60)
print("QUICK STATISTICS BY LABEL")
print("=" * 60)
print(df.groupby('label')[['duration_sec', 'total_bytes', 'total_pkts', 
                             'bytes_per_sec', 'pkts_per_sec']].mean())

print("\n" + "=" * 60)
print("CHECK: Any odd values (negative / very extreme)?")
print("=" * 60)
print(df.describe())
