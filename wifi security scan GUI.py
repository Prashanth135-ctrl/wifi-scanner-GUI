import os
import subprocess
import tkinter as tk
from tkinter import messagebox
from scapy.all import ARP, Ether, srp

# Define trusted MAC addresses
trusted_macs = ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"]
unknown_macs = []

# Function to scan network and detect MAC addresses
def scan_network():
    global unknown_macs
    unknown_macs = []  # Reset unknown MACs
    ip_range = "192.168.1.1/24"
    
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices_list.delete(0, tk.END)  # Clear previous entries

    for sent, received in answered_list:
        mac = received.hwsrc
        ip = received.psrc
        devices_list.insert(tk.END, f"{ip} - {mac}")
        if mac not in trusted_macs:
            unknown_macs.append(mac)
    
    if unknown_macs:
        messagebox.showwarning("Warning!", f"Unknown MACs detected:\n{unknown_macs}")

# Function to block a MAC address
def block_mac():
    selected = devices_list.curselection()
    if not selected:
        messagebox.showerror("Error", "Select a device to block.")
        return

    mac = devices_list.get(selected[0]).split(" - ")[1]
    router_mac = "XX:XX:XX:XX:XX:XX"  # Replace with actual router MAC
    subprocess.run(["sudo", "aireplay-ng", "-0", "5", "-a", router_mac, "-c", mac, "wlan0mon"])
    messagebox.showinfo("Blocked", f"{mac} has been blocked!")

# Function to enable monitor mode
def enable_monitor_mode():
    subprocess.run(["sudo", "airmon-ng", "start", "wlan0"])
    messagebox.showinfo("Monitor Mode", "Monitor mode enabled.")

# GUI setup
root = tk.Tk()
root.title("Wi-Fi Security Scanner")
root.geometry("500x400")

# Buttons
btn_scan = tk.Button(root, text="Scan Network", command=scan_network)
btn_scan.pack(pady=10)

btn_monitor = tk.Button(root, text="Enable Monitor Mode", command=enable_monitor_mode)
btn_monitor.pack(pady=10)

devices_list = tk.Listbox(root, width=50, height=10)
devices_list.pack(pady=10)

btn_block = tk.Button(root, text="Block Selected MAC", command=block_mac)
btn_block.pack(pady=10)

root.mainloop()
