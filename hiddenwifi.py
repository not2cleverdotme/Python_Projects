#!/bin/python3
#Inspired by Cristi Zot's Udemy course, "Python for Penetration Testers"
#Find hidden WiFi SSID networks.  This has not been tested because my Mac and Alfa card aren't playing nice.

import os
from scapy.all import *

iface = "wlan0"

def h_packet(packet):
    if packet.haslayer(Dot11ProbeReq) or packet.haslayer(Dot11ProbeResp) or packet.haslayer(Dot11AssoReq):
        print("SSID identified " + packet.info)

os.system("iwconfig " + iface + "mode monitor")

print("Sniffing traffic on interface " + iface)
sniff(iface=iface, prn=h_packet)



