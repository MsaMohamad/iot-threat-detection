import pandas as pd

print("=" * 50)
print("BOT-IOT - unique 'category' values:")
print("=" * 50)
df1 = pd.read_csv('datasets/bot-iot/reduced_data_1.csv', usecols=['category'])
print(df1['category'].value_counts())
print()

print("=" * 50)
print("UNSW-NB15 - unique 'attack_cat' values:")
print("=" * 50)
df2 = pd.read_csv('datasets/unsw-nb15/UNSW_NB15_training-set.csv', usecols=['attack_cat'])
print(df2['attack_cat'].value_counts())
print()

print("=" * 50)
print("CICIDS2017 Tuesday - unique 'Label' values:")
print("=" * 50)
df3 = pd.read_csv('datasets/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv', usecols=[' Label'])
print(df3[' Label'].value_counts())
