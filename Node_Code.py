import pandas as pd
import random
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import time

# Global run counter and schedule for attacker-free runs
run_counter = 0
next_no_attacker_run = random.randint(3, 7)

def simulate_message_flow(username, run_number, account_data):
    global next_no_attacker_run

    num_nodes = 35
    logs = []

    # Decide if this run has no attackers
    if run_number >= next_no_attacker_run:
        attacker_count = 0
        next_no_attacker_run = run_number + random.randint(3, 7)
    else:
        attacker_count = random.randint(0, 5)

    attacker_nodes = (random.sample(range(1, num_nodes + 1), attacker_count)
                      if attacker_count > 0 else [])

    base_time = datetime.now()
    for node in range(1, num_nodes + 1):
        is_attacker = node in attacker_nodes
        attack_type = random.choice(['Malicious Attack', 'Port Scan']) if is_attacker else 'Normal'
        ip_address = f'192.168.1.{node}'
        bytes_sent = (random.randint(12000, 25000) if is_attacker
                      else random.randint(100, 1000))
        duration = random.uniform(0.5, 5.0)
        throughput = round(bytes_sent / 1024 / duration, 2)
        power = round(throughput * 0.05 + random.uniform(0.5, 2.0), 2)
        login_attempts = (random.randint(5, 10) if is_attacker
                          else random.randint(1, 3))
        packet_count = (random.randint(500, 1000) if is_attacker
                        else random.randint(50, 200))
        stolen = account_data if attack_type == 'Malicious Attack' else None
        timestamp = (base_time + timedelta(seconds=node * 10)).strftime('%Y-%m-%d %H:%M:%S')

        logs.append({
            'Node Number': node,
            'Node': ip_address,
            'Attack Type': attack_type,
            'Bytes': bytes_sent,
            'Duration': duration,
            'Throughput': throughput,
            'Power': power,
            'Login Attempts': login_attempts,
            'Packet Count': packet_count,
            'Stolen Data': stolen,
            'Timestamp': timestamp,
            'Username': username if node == 1 else ''
        })

    return pd.DataFrame(logs), attacker_nodes

def detect_anomalies(df):
    features = ['Bytes', 'Duration', 'Throughput', 'Power', 'Login Attempts', 'Packet Count']
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df[features])

    model = IsolationForest(contamination=0.15, random_state=42)
    df['Anomaly Score'] = model.fit_predict(X_scaled)
    df['AI Flag'] = df['Anomaly Score'].map({1: 'Normal', -1: 'Anomalous'})
    return df

def siem_analysis(df):
    alerts = []
    df['SIEM Flag'] = 'Normal'

    for idx, row in df.iterrows():
        reasons = []
        if row['Bytes'] > 10000:
            reasons.append("High Bytes")
        if row['Stolen Data'] is not None:
            reasons.append("Stolen Credentials")
        if row['Power'] > 3:
            reasons.append("High Power")
        if row['Throughput'] > 3:
            reasons.append("High Throughput")
        if row['Login Attempts'] > 5:
            reasons.append("Excessive Login Attempts")

        if reasons:
            df.at[idx, 'SIEM Flag'] = 'Suspicious'
            alerts.append(f"{row['Node']} flagged by SIEM: {', '.join(reasons)}")

    return df, alerts

def classify_nodes(df, attacker_nodes):
    def get_level(row):
        if row['Node Number'] in attacker_nodes:
            return 'High Risk' if (row['SIEM Flag'] == 'Suspicious' and row['AI Flag'] == 'Anomalous') else 'Medium Risk'
        return 'Medium Risk' if (row['SIEM Flag'] == 'Suspicious' or row['AI Flag'] == 'Anomalous') else 'Low Risk'

    df['Threat Level'] = df.apply(get_level, axis=1)
    return df

def plot_network(df):
    G = nx.Graph()
    colors = {'Low Risk': 'green', 'Medium Risk': 'orange', 'High Risk': 'red'}

    for _, row in df.iterrows():
        G.add_node(row['Node'], threat=row['Threat Level'])

    nodes = list(df['Node'])
    for i in range(len(nodes)):
        G.add_edge(nodes[i], nodes[(i + 1) % len(nodes)])

    pos = nx.spring_layout(G, seed=42)
    node_colors = [colors[G.nodes[n]['threat']] for n in G.nodes()]

    plt.figure(figsize=(12, 8))
    nx.draw(G, pos, with_labels=True, node_color=node_colors, node_size=400, edge_color='grey')
    plt.title("Network Threat Visualization")
    plt.show()

def print_df(df, cols, delay=0.2):
    headers = " ".join(f"{c:<15}" for c in cols)
    print(f"No.  {headers}")
    for _, row in df.iterrows():
        values = " ".join(f"{str(row[c])[:15]:<15}" for c in cols)
        print(f"{row['Node Number']:<4} {values}")
        time.sleep(delay)

def main():
    global run_counter
    run_counter += 1

    msg = input("Enter the message to send across the network: ")
    account_data = {'username': msg, 'password': msg}

    df, attackers = simulate_message_flow(msg, run_counter, account_data)
    print("\n--- Log Sample (first 5 rows) ---")
    print_df(df.head(), ['Node', 'Attack Type', 'Bytes', 'Throughput', 'Power'])

    df = detect_anomalies(df)
    df, alerts = siem_analysis(df)
    df = classify_nodes(df, attackers)

    print("\n--- SIEM Alerts ---")
    print("\n".join(alerts) if alerts else "No SIEM alerts detected.")

    print("\n--- Final Threat Classification ---")
    print_df(df, ['Node', 'Threat Level', 'SIEM Flag', 'AI Flag'], delay=0.1)

    plot_network(df)

if __name__ == "__main__":
    main()
