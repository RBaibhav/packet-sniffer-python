from scapy.all import sniff, IP, TCP, UDP 
import time 

def packet_callback(packet):
    # check if this packet has an IP layer 
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = f"Protocol-{protocol}"
            

        print(f"{src_ip:15} -> {dst_ip:15}  [{protocol_name}]")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            if dst_port == 80 or dst_port == 443:
                print("   ^ HTTPS web traffic detected")

print("starting packet cature.... ") 
print("Source IP       -> Destination IP   [protocol]")
print('-' * 50)


try: 
    sniff(prn = packet_callback, count = 5, timeout = 10)
except PermissionError:
    print("\n❌ Permission denied!")
    print("💡 You need to run this with: sudo python3 packet_test.py")
    print("💡 This is exactly what you predicted!")
except Exception as e:
    print(f"something went wrong: {e}")

print("\n✅ Packet capture finished!")