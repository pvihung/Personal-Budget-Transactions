import pandas as pd
import matplotlib.pyplot as plt
#import seaborn as sns


data = pd.read_csv('../dataset/personal-finance-budgeting-records-with-user-info.csv')

# Get the information needed
df = data.copy()

# Checking data
# The data, overall, look clean

# We might want to handle the null data in recurrence_interval as None
df['recurrence_interval'] = df['recurrence_interval'].fillna('none')

# Replace household_id and record_id into Integer for easier handling
# Change household_id to user_id
def cleaning_id(text):
    text = str(text).strip()
    text = text.replace('HH', '')
    text = text.replace('REC', '')
    return text

df['user_id'] = df['household_id'].apply(cleaning_id)
df['user_id'] = pd.to_numeric(df['user_id'])

df['record_id'] = df['record_id'].apply(cleaning_id)
df['record_id'] = pd.to_numeric(df['record_id'])

# Checking datetime
df['transaction_date'] = pd.to_datetime(df['transaction_date'], format='%m/%d/%Y')

# Reorder column
re_columns = list(df.columns)
re_columns = ['record_id'] + ['user_id'] + [col for col in re_columns if (col != 'record_id' and col != 'user_id')]
df = df[re_columns]


# Final dataframe
df = df.drop_duplicates(subset= ['record_id'], keep = 'first')
final_df = df.drop(columns=['household_id', 'subcategory', 'description', 'payer_payee', 'is_recurring', 'recurrence_interval'])
final_df.to_csv('../dataset/final_df.csv', index=False)

final_records = final_df.drop(columns=['user_name', 'email', 'password', 'household_size', 'location_city', 'location_state', 'location_postal_code', 'location_country'])
final_records.to_csv('../dataset/final_records.csv', index=False)

final_user = final_df[['user_id', 'user_name', 'email', 'password', 'household_size', 'location_city', 'location_state', 'location_postal_code', 'location_country']]
final_user.to_csv('../dataset/final_user.csv', index=False)