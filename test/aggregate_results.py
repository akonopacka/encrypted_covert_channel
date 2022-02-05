import glob
import pandas as pd

folder_path = "/home/ak/results/"
# files = os.listdir(folder_path)
files = glob.glob("/home/ak/results/*.csv")

print("--- Aggregating data ---")

results_client = pd.DataFrame()
results_server = pd.DataFrame()
results_chart = pd.DataFrame()
files.sort()
print("FILES: ",files)
counter = 3
for file in files:
    print("Processing file", file)
    # file_path = folder_path + file
    try:
        df = pd.read_csv(file, sep=';', header=None)
        print(df)
        df = df.apply(pd.to_numeric, errors='coerce')
        print(df)
        mean = df.mean(axis=0)
        std = df.std()
        is_client = file.startswith('/home/ak/results/_client')
        is_server = file.startswith('/home/ak/results/_server')
        print("MEAN:")
        print(mean)
        print("STD: ")
        print(std)
        print("--------------------------------------------")

        if is_client:
            configuration = file.replace('/home/ak/results/_client_', '')
            configuration = configuration.replace('.csv', '')
            mean.name = configuration
            std.name = configuration + '_std'
            results_client = results_client.append(mean)
            results_client = results_client.append(std)
        if is_server:
            configuration = file.replace('/home/ak/results/_server_', '')
            configuration = configuration.replace('.csv', '')
            mean.name = configuration
            std.name = configuration + '_std'
            results_chart.name = configuration
            results_server = results_server.append(mean)
            results_server = results_server.append(std)

    except pd.errors.EmptyDataError:
        print("No columns to parse from file : ", file)

    counter = counter + 2

print("Results client : ", results_client)
print("Results server : ", results_server)
results_client.to_csv("/home/ak/results/results_client.csv")
results_server.to_csv("/home/ak/results/results_server.csv")
