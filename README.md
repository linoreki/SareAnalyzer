![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![Scapy Version](https://img.shields.io/badge/scapy-latest-orange.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux-lightgrey.svg)

## Description

**SareAnalyzer** is a network analysis tool written in Python that allows for port scanning, packet capturing, and host detection on a network. This tool is designed to help network administrators and security enthusiasts better understand their network infrastructure.

## Features

- **TCP and UDP port scanning**: Performs a port scan to identify open services on a specific host.
- **Packet capturing**: Listens and captures network traffic on a specific interface.
- **Host detection**: Identifies active devices on the local network using ARP.

## Installation

### Prerequisites

- Python 3.x
- `pip` (Python package manager)

### Repository installation:

   ```sh
   git clone https://github.com/yourusername/SareAnalyzer.git
   cd SareAnalyzer
   ```

### Install the required dependencies:

  ```sh
  pip install -r requirements.txt
   ```

### Additional dependencies for Windows

For Windows users, it is recommended to install Npcap for packet capturing. You can download Npcap from [here](https://npcap.org).

## Usage

To start the tool, simply run the `SareAnalyzer.py` file:

  ```sh
  python SareAnalyzer.py
  ```
