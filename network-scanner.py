#!/usr/bin/python3

import ipaddress
from scapy.all import Ether, ARP, srp
from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup
from argparse import ArgumentParser
from sys import exit, stderr

class NetworkScanner:
    def __init__(self, hosts, timeout=1):
        self.hosts = hosts
        self.alive = {}
        self.timeout = timeout
        self.packet = self.create_packet()
        self.send_packet()
        self.print_alive()

    def create_packet(self):
        layer1 = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Send ARP requests to each host in the range
        self.packets = [layer1 / ARP(pdst=str(ip)) for ip in self.hosts]

    def send_packet(self):
        for packet in self.packets:
            answered, unanswered = srp(packet, timeout=self.timeout, verbose=False)
            if answered:
                for sent, received in answered:
                    self.alive[received.psrc] = received.hwsrc
            else:
                print("No hosts are alive.")
                exit(1)

    def print_alive(self):
        table = PrettyTable(["IP", "MAC", "VENDOR"])
        for ip, mac in self.alive.items():
            try:
                vendor = MacLookup().lookup(mac)
            except Exception:
                vendor = "UNKNOWN"
            table.add_row([ip, mac, vendor])
        print(table)

def get_args():
    parser = ArgumentParser(description="Network scanner")
    parser.add_argument("--hosts", dest="hosts", help="Host IP or IP range (e.g., 192.168.1.0/24)", required=True)
    parser.add_argument("--timeout", dest="timeout", type=int, help="Timeout for each host response", default=1)
    args = parser.parse_args()

    # Expand CIDR notation if provided
    try:
        hosts = [str(ip) for ip in ipaddress.IPv4Network(args.hosts, strict=False)]
    except ValueError:
        print("Invalid IP range provided. Please use a valid IP address or CIDR notation.")
        exit(1)

    return hosts, args.timeout

hosts, timeout = get_args()
NetworkScanner(hosts, timeout)
