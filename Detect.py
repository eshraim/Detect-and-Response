import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import psutil
import socket
import threading
import requests
import os

# Set up logging
import logging
logging.basicConfig(filename='network_analysis.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Capture network traffic
def capture_packets(interface, packet_count, packet_storage):
    packets = scapy.sniff(iface=interface, count=packet_count)
    packet_storage.extend(packets)

# Extract features from captured packets
def extract_features(packets):
    features = []
    for packet in packets:
        feature = []
        feature.append(len(packet))  # Packet length
        if IP in packet:
            feature.append(packet[IP].ttl)  # Time to live
            feature.append(packet[IP].proto)  # Protocol
            feature.append(packet[IP].src)  # Source IP
            feature.append(packet[IP].dst)  # Destination IP
        else:
            feature.extend([0, 0, '', ''])
        if TCP in packet:
            feature.append(packet[TCP].dport)  # Destination port
            feature.append(packet[TCP].sport)  # Source port
            feature.append(int(packet[TCP].flags))  # TCP flags (converted to int)
            feature.append(len(packet[TCP].payload))  # Payload length
        else:
            feature.extend([0, 0, 0, 0])
        features.append(feature)
    return features

# Automated incident response
def block_ip(ip):
    os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
    logging.info(f"Blocked IP address: {ip}")

# Fetch threat intelligence data from a public source
def fetch_public_threats():
    # Use a public source of malicious IPs (for demonstration purposes, we'll use a mock URL)
    public_threats_url = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
    response = requests.get(public_threats_url)
    threat_ips = response.text.splitlines()
    return threat_ips

# Visualize packets
def visualize_packets(df):
    plt.figure(figsize=(12, 8))
    plt.scatter(df['length'], df['ttl'], color='blue', label='Packets')
    plt.xlabel('Packet Length')
    plt.ylabel('Time to Live (TTL)')
    plt.legend()
    plt.title('Network Traffic')
    plt.savefig('network_traffic.png')
    plt.show()

# Save features to a file
def save_results(df):
    df.to_csv('network_analysis_results.csv', index=False)

# Main function
def main():
    interface_name = 'Wi-Fi'
    interface = interface_name
    packet_count = 3000

    # Capture packets
    packet_storage = []
    capture_thread = threading.Thread(target=capture_packets, args=(interface, packet_count, packet_storage))
    capture_thread.start()
    capture_thread.join()
    print(f"Captured {len(packet_storage)} packets from {interface_name}")

    # Extract features
    features = extract_features(packet_storage)
    df = pd.DataFrame(features, columns=['length', 'ttl', 'proto', 'src_ip', 'dst_ip', 'dport', 'sport', 'flags', 'payload_len'])

    # Save results
    save_results(df)

    # Visualize packets
    visualize_packets(df)

    # Integrate with public threat intelligence
    try:
        public_threats = fetch_public_threats()
        print("Fetched public threat intelligence data")
        
        # Check for matches
        matching_ips = df[df['src_ip'].isin(public_threats)]['src_ip'].unique()
        num_matches = len(matching_ips)
        
        print(f"Number of matching IPs: {num_matches}")
        if num_matches > 0:
            for ip in matching_ips:
                block_ip(ip)
                logging.info(f"Detected and blocked threat IP: {ip}")
    except Exception as e:
        logging.error(f"Error fetching public threats: {e}")
        print("Error fetching public threats")

# Run the main function
if __name__ == "__main__":
    main()
