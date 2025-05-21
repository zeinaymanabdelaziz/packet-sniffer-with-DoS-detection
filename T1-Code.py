from scapy.all import sniff
from collections import Counter
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import time

# Global variables for traffic statistics
protocol_count = Counter()
large_packet_threshold = 1500  # Set the threshold for "large packets"
protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}  # Mapping protocol numbers to names
packet_times = []  # To track packet arrival times for DoS detection
dos_threshold = 100  # Default DoS detection threshold
stop_sniffing = False  # Flag to stop sniffing
average_pps = 0  # Average packets per second

# Function to calculate average packets per second
def calculate_average_pps(duration=10):
    """Performs a brief sniffing session to calculate average packets per second."""
    start_time = time.time()
    packets_captured = []

    def count_packets(packet):
        packets_captured.append(packet)

    print("Calculating average packets per second...")
    sniff(prn=count_packets, timeout=duration, count=0)  # Sniff for the specified duration
    elapsed_time = time.time() - start_time
    packet_count = len(packets_captured)
    avg_pps = packet_count / elapsed_time if elapsed_time > 0 else 0
    print(f"Sniffed {packet_count} packets in {elapsed_time:.2f} seconds. Average PPS: {avg_pps:.2f}")
    return avg_pps

# GUI Functions
def update_threshold():
    global dos_threshold
    try:
        dos_threshold = int(threshold_entry.get())
        messagebox.showinfo("Update Successful", f"DoS threshold updated to {dos_threshold} packets/sec")
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid integer.")

def display_log(message):
    log_area.insert(tk.END, message + "\n")
    log_area.see(tk.END)

def update_protocol_stats():
    """Updates the real-time protocol statistics in the GUI."""
    stats_display.delete("1.0", tk.END)
    for proto, count in protocol_count.items():
        proto_name = protocol_names.get(proto, f"Unknown ({proto})")
        stats_display.insert(tk.END, f"{proto_name}: {count} packets\n")
    stats_display.see(tk.END)

# Stop Sniffing
def stop_sniffing_handler():
    global stop_sniffing
    stop_sniffing = True
    display_log("Stopping packet sniffing...")
    messagebox.showinfo("Sniffer Stopped", "Packet sniffing has been stopped.")

# Packet Flooding (DoS Detection)
def detect_flood():
    global packet_times, stop_sniffing
    current_time = time.time()
    packet_times.append(current_time)

    # Remove timestamps older than 1 second
    packet_times = [t for t in packet_times if t > current_time - 1]

    if len(packet_times) > dos_threshold:  # Threshold for DoS detection
        alert_message = f"ALERT: Potential DoS attack detected! Packet rate exceeded {dos_threshold} packets/sec."
        display_log(alert_message)
        stop_sniffing = True  # Stop sniffing automatically on DoS attack
        messagebox.showwarning("DoS Alert", "Sniffing stopped due to a detected DoS attack.")

# Packet Handler Function
def packet_handler(packet):
    global protocol_count

    # Include Timestamp for Packets
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    display_log(f"Timestamp: {timestamp}")

    # Update Traffic Statistics
    if packet.haslayer("IP"):
        proto = packet['IP'].proto
        protocol_count[proto] += 1
        update_protocol_stats()  # Update protocol statistics in the GUI

    # Enhanced Output Formatting
    if packet.haslayer("IP"):
        proto_name = protocol_names.get(packet['IP'].proto, f"Unknown ({packet['IP'].proto})")
        display_log(f"Source IP: {packet['IP'].src} -> Destination IP: {packet['IP'].dst} (Protocol: {proto_name})")

    if len(packet) > large_packet_threshold:
        alert_message = f"ALERT! Large packet detected! Size: {len(packet)} bytes"
        display_log(alert_message)

    # Detect Packet Flooding (DoS Detection)
    detect_flood()

# Stop Filter for Scapy Sniff
def sniff_stop_filter(packet):
    global stop_sniffing
    return stop_sniffing  # Stop sniffing when the flag is True

# Start Sniffing in a Background Thread
def start_sniffing():
    global stop_sniffing
    stop_sniffing = False  # Reset stop flag
    display_log("Starting packet sniffing...")
    sniff(prn=packet_handler, stop_filter=sniff_stop_filter, count=0)
    display_log("Packet sniffing stopped.")

def start_sniffing_thread():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

# GUI Setup
def setup_gui():
    global root, threshold_entry, log_area, stats_display
    root = tk.Tk()
    root.title("Packet Sniffer with DoS Detection")
    root.geometry("800x600")

    threshold_label = tk.Label(root, text="DoS Detection Threshold (packets/sec):")
    threshold_label.pack(pady=5)

    threshold_entry = tk.Entry(root)
    threshold_entry.insert(0, str(dos_threshold))
    threshold_entry.pack(pady=5)

    threshold_info = tk.Label(root, text=f"Average Packets/Sec: {average_pps:.2f}. Suggested threshold: {int(average_pps * 1.5)}")
    threshold_info.pack(pady=5)

    update_button = tk.Button(root, text="Update Threshold", command=update_threshold)
    update_button.pack(pady=5)

    log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=10)
    log_area.pack(pady=10)

    stats_label = tk.Label(root, text="Protocol Statistics (Real-Time):")
    stats_label.pack(pady=5)

    stats_display = tk.Text(root, wrap=tk.WORD, width=90, height=10, state=tk.NORMAL)
    stats_display.pack(pady=10)

    start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing_thread)
    start_button.pack(pady=5)

    stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing_handler)
    stop_button.pack(pady=5)

if __name__ == "__main__":
    # Calculate average PPS before starting the GUI
    average_pps = calculate_average_pps(duration=10)
    dos_threshold = int(average_pps * 1.5)  # Set initial threshold to 1.5x the average PPS

    setup_gui()
    root.mainloop()