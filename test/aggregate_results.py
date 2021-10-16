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
counter = 3
for file in files:
    print("Processing file", file)
    # file_path = folder_path + file
    try:
        df = pd.read_csv(file, sep=';', header=None)
        # print (df)
        mean = df.mean(axis=0)
        is_client = file.startswith('/home/ak/results/general/_client')
        is_server = file.startswith('/home/ak/results/general/_server')

        if is_client:
            configuration = file.replace('/home/ak/results/general/_client_', '')
            configuration = configuration.replace('.csv', '')
            mean.name = configuration
            results_client = results_server.append(mean)
        if is_server:
            configuration = file.replace('/home/ak/results/general/_server_', '')
            configuration = configuration.replace('.csv', '')
            mean.name = configuration
            results_server = results_server.append(mean)

    except pd.errors.EmptyDataError:
        print("No columns to parse from file : ", file)

    counter = counter + 2

print("Results client : ", results_client)
print("Results server : ", results_server)
results_client.to_csv("/home/ak/results/results_client.csv")
results_server.to_csv("/home/ak/results/results_server.csv")
