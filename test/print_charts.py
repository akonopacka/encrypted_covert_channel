import plotly.express as px
import pandas as pd
df = pd.read_csv('/home/ak/results/base_07_01/results_chart.csv')
print(df)
fig = px.strip(df, x="Covert channel method", y="Capacity [bits/ms]", color="Cryptography algorithm")
fig.update_traces(marker_size=14)
fig.update_layout(legend_font_size=15)
fig.update_layout(
    yaxis = dict(
        tickfont = dict(size=15)))
fig.update_layout(
    xaxis = dict(
        tickfont = dict(size=15)))
fig.show()