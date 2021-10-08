import os
import csv
import pandas as pd
import glob



folder_path = "/home/ak/results/general/"
# files = os.listdir(folder_path)
files = glob.glob("/home/ak/results/general/*.csv")

print("--- Aggregating data ---")

results_client = pd.DataFrame()
results_server = pd.DataFrame()
for file in files:
    print("Processing file", file)
    # file_path = folder_path + file
    try:
        df = pd.read_csv (file, sep=';', header=None)
        # print (df)
        mean = df.mean(axis = 0)
        print(mean)
        is_client = file.startswith('/home/ak/results/general/_client')
        if is_client:
            results_client = results_client.append(mean, ignore_index=True)
        else:
            results_server = results_server.append(mean, ignore_index=True)

    except pd.errors.EmptyDataError:
        print("No columns to parse from file : ", file)

print("Results client : ", results_client)
print("Results server : ", results_server)
results_client.to_csv("/home/ak/results/general/results_client.csv")
results_server.to_csv("/home/ak/results/general/results_server.csv")
