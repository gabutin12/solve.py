import pyshark

capture = pyshark.FileCapture('./capture.pcapng', display_filter='udp and ip.dst == 172.17.0.3 and !icmp')

data = []
for pkt in capture:
    try:
        data.append(pkt.data.data)
    except:
        pass
print(data)