# Multi-Threaded Port Scanner
A high-speed, multi-threaded Python port scanner designed for cybersecurity and ethical hacking.

# Features  
- Scans a range of ports on any IPv4 host
- Multi-threaded scanning (default: 500 threads)
- Identifies open ports and services
- Fast, efficient, and retry-based to reduce false negatives
- Verbose mode for detailed results

# Installation
Clone the repository:
git clone https://github.com/shaily2001/port-scanner.git
cd port-scanner

# Usage
Basic Scan:
Scan the default port range (1-65535) on a target IP:
python port_scanner.py 192.168.1.1

# Custom Port Range:
Specify a custom port range and number of threads:
python sport_scanner -s 20 -e 4000 -t 500 192.168.1.1

# Verbose Output:
Use the -V option to get more detailed output:
python port_scanner -V 192.168.1.1

