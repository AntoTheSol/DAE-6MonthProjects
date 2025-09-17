import pandas as pd

# Create a DataFrame
data = {
    'Name': ['Alice', 'Bob', 'Charlie'],
    'Age': [25, 30, 35],
    'Salary': [70000, 80000, 120000]
}
df = pd.DataFrame(data)

# Accessing data
df['Age']           # Series
df.iloc[0]          # First row
df.loc[0, 'Salary'] # Cell

# Filtering
df[df['Age'] > 28]

# Adding a column
df['Tax'] = df['Salary'] * 0.2

# Summary stats
df.describe()
