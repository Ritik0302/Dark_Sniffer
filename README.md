# Dark_Sniffer
file:///home/whitedevil/Desktop/Screenshot%20from%202024-08-01%2012-05-51.jpg


**Dark-Sniffer** is a tool designed for educational purposes. This tool is created to be user-friendly and demonstrates the use of Python dictionaries along with essential modules for Network Sniffing.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Modules Required](#modules-required)
- [Disclaimer](#disclaimer)

## Installation

To run this tool, you need to have Python installed on your system. Additionally, you must install two main Python modules: `scapy` and `urllib`. You can install these modules using pip:

```sh
pip install scapy
from urllib.parse import parse_qs
```
## Usage
```sh
git clone https://github.com/Ritik0302/Dark_Sniffer.git
cd Dark_Sniffer/
python3 Dark_Sniffer.py
```
Enter the interface name when prompted.

## Stop the script:
Press Ctrl+C to stop sniffing.

## IMPORTANT NOTE
Run this on root user only....

## Required hardware

To use this tool and capture credentials from users connected to the same network, you need a Wi-Fi adapter that supports monitor mode. For testing purposes, you can set up a virtual environment using VirtualBox or VMware. Create virtual machines and connect them using a NAT network. Use `eth0` as the interface to test the tool.

## Modules Required
This tool relies on the following Python modules:

scapy: This is a powerful Python library used for packet manipulation and network analysis. It provides functionalities for creating, sending, and analyzing network packets.

urllib.parse: This is part of Python's standard library and provides functions for parsing URLs and query strings.
## Disclaimer
This tool is intended solely for educational purposes. Unauthorized use of this tool on networks you do not own or have explicit permission to test is illegal and unethical. Use this tool responsibly.

Author: Ritik Singhania
Contact: ritiksinghania0302@gmail.com
