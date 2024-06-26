#!/usr/bin/env python

from scapy.all import TCP, sniff, TCPSession
import sys
from plot_utils import *

def find_timestamp(pkt):
    for option in pkt[TCP].options:
        if option[0] == 'Timestamp':
            return int(option[1][1] or 0)

    return 0

def find_actual_time(pkt):
    return int(pkt.time or 0)

def process_pkt(pkt):
    add_point(find_actual_time(pkt), find_timestamp(pkt) / 1000)

def read_packets_from_file(file):
    if(file == "-"):
        file = sys.stdin.buffer
    else:
        file = open(file, "rb")

    sniff(offline=file, session=TCPSession, store=False, prn=process_pkt)

def main():

    if(len(sys.argv) != 2):
        print("Numero errato di arg")
    
    filename = sys.argv[1]

    print(filename)

    try:
        read_packets_from_file(filename)
    except KeyboardInterrupt:
        print("\b\bTerminated by the user.")
    finally:
        plot()

if __name__ == '__main__':
    main()
