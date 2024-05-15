from scapy.all import *
from collections import namedtuple

packets = rdpcap('capture.pcapng')

Packet = namedtuple("Packet", "src_port payload")

payload_packets = []

for packet in packets:
    if not packet.haslayer(IP):
        continue
    if not packet.haslayer(UDP):
        continue
    if not packet[IP].src == "172.17.0.2":
        continue
    if not packet[IP].dst == "172.17.0.3":
        continue
    if not packet[UDP].dport == 56742:
        continue
    if not len(packet[UDP].payload) == 1:
        continue

    payload_packets.append(Packet(packet[UDP].sport, bytes(packet[UDP].payload)))

print(len(payload_packets))