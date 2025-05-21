# Packet Sniffer with DoS Detection

A real-time Python-based packet sniffer with Denial-of-Service (DoS) detection, developed for the **Computer Networks** course.  
It uses **Scapy** for packet capture and **Tkinter** for a graphical interface, offering protocol analysis and dynamic alerting.

# Project Overview

This project aims to monitor and analyze network traffic, detect potential DoS attacks based on abnormal packet rates, and display real-time statistics in a user-friendly GUI.

# Key Features

- 📡 **Real-Time Packet Sniffing** using `scapy.sniff()`
- 📊 **Protocol Analysis** for ICMP, TCP, and UDP
- 🚨 **DoS Detection** using a dynamic threshold (1.5× average PPS)
- 👁️‍🗨️ **Live Logging Interface** with packet stats and alerts
- 🛑 **Auto-Halt on Attack Detection** to prevent system overload
- 🖥️ **Tkinter GUI** with:
  - Start/Stop sniffing controls
  - Editable DoS detection threshold
  - Scrollable live log viewer

# Technologies Used

- **Python**
- **Scapy** – Packet capture and network inspection
- **Tkinter** – GUI for live interaction
- **Threading** – For non-blocking packet sniffing

# File Structure

📦 Packet_Sniffer_DoS_Detection
<br>├── T1-Code.py # Main Python source file
<br>├── T1-Report.pdf # Detailed technical report

# System Workflow

1. **Startup**: Calculates average packets per second (PPS) for 10 seconds
2. **Sniffing Begins**: Captures incoming packets, logs protocol/type/size/IP
3. **Live Updates**: Protocol stats update in the GUI
4. **DoS Alert**: If packet rate > 1.5× average PPS → alert & auto-stop
5. **User Controls**: Threshold can be adjusted; sniffing can be manually stopped

# Sample Use Cases

- 🏫 **Education**: Demonstrates traffic analysis and basic IDS principles
- 🧑‍💻 **Network Admins**: Monitor and alert on abnormal activity
- 🧩 **SMBs**: Lightweight tool for early DoS detection without complex systems

# Example Log Entry

| Timestamp           | Source IP     | Destination IP | Protocol | Size (bytes) |
|---------------------|---------------|----------------|----------|--------------|
| 2024-12-16 14:32:21 | 192.168.1.5   | 192.168.1.10   | TCP      | 1500         |

# Future Enhancements

- Add filtering by IP or port
- Enable log export (CSV)
- Advanced threat classification (SYN flood, Ping of Death)
- Live charting of traffic metrics

# License
<br>This project is for academic and educational use only.
