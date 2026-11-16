import pandas as pd

for i in range(1, 5):
    print("=" * 50)
    print(f"BOT-IOT FILE {i}: reduced_data_{i}.csv")
    print("=" * 50)
    df = pd.read_csv(f'datasets/bot-iot/reduced_data_{i}.csv', usecols=['category', 'subcategory'])
    print(df['category'].value_counts())
    print("---subcategory---")
    print(df['subcategory'].value_counts())
    print()
