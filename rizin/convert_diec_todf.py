import re
from pathlib import Path
import sys

text = Path("./rizin/diec_results.txt").read_text()

# Initialize an empty dictionary
result = {}

# Split the text by lines
lines = text.strip().split('\n')
# Initialize variables
current_key = None
current_info = {}

# Iterate over the lines
for line in lines:
    line = line.strip()

    # Check if the line is a file path
    if line.startswith('/Users'):
        # If there is existing information, add it to the result dictionary
        if current_key and current_info:
            result[current_key] = current_info

        # Extract the file path
        if "Practical Malware" in line:
            current_key = str(line[:-9]).strip()
        else:
            current_key = str(line.split()[0]).strip()
            current_info = {}

    # Check if the line contains key-value pairs
    elif 'Compiler:' in line or "Linker:" in line:
        key, value = map(str.strip, line.split(':', 1))
        current_info[key] = value

# Add the last file information to the result dictionary
if current_key and current_info:
    result[current_key] = current_info

import pandas as pd
unique_columns = ["Compiler", "Linker"]
df = pd.read_excel("./allMatches.xls")

df = df.assign(**{column: '' for column in unique_columns})

df_dict = df.set_index(' PE Paths ').to_dict(orient='index')

for key in df_dict.keys():
    if str(key).strip() in result:
        file_result = result[str(key).strip()]
        for k, value in file_result.items():
            df_dict[key][k] = value
    else:
        print(key)
df = pd.DataFrame.from_dict(df_dict, orient='index')
print(df)
df.to_excel("updatedMatches.xlsx", index=True)

