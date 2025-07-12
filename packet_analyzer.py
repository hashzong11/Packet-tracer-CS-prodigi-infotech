# deepnet/packet_analyzer.py
from tkinter import ARC
from scapy.all import IP, TCP, UDP, ICMP, DNS, HTTP, Raw
from .utils import timestamp_to_str, format_hexdump
import socket

class PacketAnalyzer:
    @staticmethod
    def get_protocol(packet):
        """Determine packet protocol"""
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ARC):
            return "ARP"
        return "Other"

    @staticmethod
    def get_ip_info(packet):
        """Extract IP layer information"""
        if not packet.haslayer(IP):
            return None, None, None, None
        
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        ttl = ip.ttl
        length = ip.len
        return src, dst, ttl, length

    @staticmethod
    def get_transport_info(packet):
        """Extract transport layer information"""
        proto = PacketAnalyzer.get_protocol(packet)
        sport, dport = None, None
        
        if proto == "TCP" and packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif proto == "UDP" and packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        return sport, dport, proto

    @staticmethod
    def get_payload(packet):
        """Extract payload data"""
        if packet.haslayer(Raw):
            return bytes(packet[Raw].load)
        return None

    @staticmethod
    def analyze_packet(packet):
        """Comprehensive packet analysis"""
        analysis = {
            'timestamp': timestamp_to_str(packet.time),
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'src_port': None,
            'dst_port': None,
            'size': len(packet),
            'payload': None,
            'hexdump': None,
            'info': ''
        }

        # Extract IP information
        if packet.haslayer(IP):
            src, dst, ttl, length = PacketAnalyzer.get_ip_info(packet)
            analysis['src_ip'] = src
            analysis['dst_ip'] = dst
            analysis['info'] = f"TTL={ttl} Len={length}"

        # Extract transport layer info
        sport, dport, proto = PacketAnalyzer.get_transport_info(packet)
        analysis['protocol'] = proto
        analysis['src_port'] = sport
        analysis['dst_port'] = dport

        # Add port info to display
        if sport and dport:
            analysis['info'] += f" Ports: {sport}→{dport}"

        # Extract payload
        payload = PacketAnalyzer.get_payload(packet)
        if payload:
            analysis['payload'] = payload
            analysis['hexdump'] = format_hexdump(payload)
            
            # Try to decode HTTP
            if proto == 'TCP' and (dport == 80 or sport == 80):
                try:
                    http = HTTP(payload)
                    if http:
                        analysis['info'] += " HTTP"
                except:
                    pass
            
            # Try to decode DNS
            if proto == 'UDP' and (dport == 53 or sport == 53):
                try:
                    dns = DNS(payload)
                    if dns:
                        analysis['info'] += " DNS"
                except:
                    pass

        return analysis