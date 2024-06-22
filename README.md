# Network Traffic Detection and Response

This project captures network traffic, extracts features, integrates threat intelligence, and automates incident response by blocking detected threat IPs using a threat hunting repository via an API call. 

## Requirements

Ensure you have the following Python packages installed:

- `scapy`
- `pandas`
- `matplotlib`
- `numpy`
- `psutil`
- `requests`

Install them with:

```
pip install scapy pandas matplotlib numpy psutil requests
```

## Running the Script

1. **Clone the Repository**:

```
git clone https://github.com/eshraim/Detect-and-Response.git
cd Detect-and-Response
```

2. **Run the Script**:

```
python Detect.py
```

## How It Works

1. **Capture Packets**: Captures network packets from the specified interface.
2. **Extract Features**: Extracts features such as packet length, TTL, protocol, source IP, destination IP, ports, TCP flags, and payload length.
3. **Visualize Packets**: Plots a graph of the captured network traffic.
4. **Save Results**: Saves extracted features to a CSV file.
5. **Fetch Public Threats**: Retrieves threat intelligence data from a public repository via API call.
6. **Match and Block IPs**: Checks for matches with threat IPs and blocks them.

## Configuration

- Set the `interface_name` variable to your network interface (e.g., 'Wi-Fi').

```
interface_name = 'Wi-Fi'
```

- Set the `packet_count` variable to the number of packets to capture.

```
packet_count = 3000
```

## Output

- Prints the number of captured packets.
- Saves extracted features to `network_analysis_results.csv`.
- Plots a graph of the network traffic and saves it as `network_traffic.png`.
- Logs detected and blocked threat IPs to `network_analysis.log`.
