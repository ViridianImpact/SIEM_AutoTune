from elasticsearch import Elasticsearch
from splunklib import client

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

es = Elasticsearch(['https://your-es-url'])
response = es.search(index="siem-alerts", body={"query": {"match_all": {}}})

df = pd.read_csv('siem_data.csv')
# Clean up missing/invalid data
df.dropna(subset=['rule_name', 'alert_status'], inplace=True)

sns.barplot(x='rule_name', y='false_positive_rate', data=df)
plt.show()

def calculate_false_positives(data):
    rule_stats = data.groupby('rule_name').apply(
        lambda x: x[x['alert_status'] == 'false_positive'].shape[0] / x.shape[0]
    )
    return rule_stats

def recommend_tuning(rules_stats, threshold=0.5):
    recommendations = []
    for rule, rate in rules_stats.items():
        if rate > threshold:
            recommendations.append(f"Adjust or disable {rule}, false positive rate: {rate:.2f}")
    return recommendations

def main():
    rules_stats = calculate_false_positives('siem_data.csv')
    recommendations = recommend_tuning(rules_stats)

    # Connect to Splunk Client
    splunk_service = client.connect(host='localhost', port=8089, username='admin', password='password')
    # Automate rule adjustments
    for rule in recommendations:
        # Adjust rule threshold or status in Splunk
        pass
