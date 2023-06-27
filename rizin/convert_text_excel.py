import os
import re
from pathlib import Path

folder_path = "./rizin/diec_results/"

all_results = {}
unique_columns = []
# Iterate over the files in the folder
for filename in os.listdir(folder_path):
    # Remove leading and trailing whitespaces
    filename = Path(filename)
    file = Path("/Users/ayush.goel/Documents/GitHub/capa/rizin/diec_results/" +filename.stem + ".txt")
    file_exe = filename.stem
    

    # Split the text into lines
    lines = file.read_text().split('\n')

    # Initialize the dictionary
    result_dict = {}

    # Process each line
    for line in lines:
        line = line.strip()

        # If the line starts with a word followed by a colon, it indicates a new key
        if re.match(r'^\w+:', line):
            # Extract the new key
            current_key = line.split(':')[0].strip()
            if current_key not in unique_columns:
                unique_columns.append(current_key)
            current_value = line.split(':')[1].strip()
            result_dict[current_key] = current_value

    # Add the filename key-value pair to the result dictionary
    if "ping" in file_exe:
        file_exe = "ping_t√§st"
    file_exe = file_exe.replace("_", " ")
    all_results[file_exe.strip()] =  result_dict

print(unique_columns)

import pandas as pd

df = pd.read_excel("./allMatches.xls")

df = df.assign(**{column: '' for column in unique_columns})

df_dict = df.set_index(' PE Paths ').to_dict(orient='index')

all_keys = all_results.keys()

for key in df_dict.keys():
    new_key = Path(str(key)).stem.replace("_", " ")
    results = all_results[new_key]
    for k, value in results.items():
        df_dict[key][k] = value
df = pd.DataFrame.from_dict(df_dict, orient='index')
df.to_excel("updatedMatches.xlsx", index=True)

    
