import pandas as pd

print("=" * 60)
print("BOT-IOT DATASET (reduced_data_1.csv)")
print("=" * 60)
df1 = pd.read_csv('datasets/bot-iot/reduced_data_1.csv', nrows=5)
print("Columns:", df1.columns.tolist())
print(df1.head(3))
print()

print("=" * 60)
print("UNSW-NB15 TRAINING SET")
print("=" * 60)
df2 = pd.read_csv('datasets/unsw-nb15/UNSW_NB15_training-set.csv', nrows=5)
print("Columns:", df2.columns.tolist())
print(df2.head(3))
print()

print("=" * 60)
print("CICIDS2017 - TUESDAY (Brute Force)")
print("=" * 60)
df3 = pd.read_csv('datasets/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv', nrows=5)
print("Columns:", df3.columns.tolist())
print(df3.head(3))
