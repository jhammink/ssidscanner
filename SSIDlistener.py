#!/usr/bin/env python

from scapy.all import *

ssids={}

def PacketHandler(pkt):
    if pkt.haslayer(scapy.all.Dot11):
        if pkt.type == 0 and pkt.subtype == 4:
            if not pkt.addr2 in ssids:
                ssids[pkt.addr2]=set()
                ssids[pkt.addr2].add(pkt.info)
                print("")
                for ssid in ssids:
                        print(ssid,ssids[ssid])

sniff(iface="wlan0mon", prn=PacketHandler)
