import pandas as pd

def verify_column_values(df, column_name, value_list):
    return df[column_name].isin(value_list).all()

def get_unique_values(df, column_name):
    return df[column_name].unique()

# Example usage
df = pd.DataFrame({'A': [1, 2, 3, 2, 4], 'B': [10,11,12,13,14]})
value_list = [1, 2, 3]

print(df[(df['A'] == 2) | (df['B'] == 10)])



