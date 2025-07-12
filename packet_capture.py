# deepnet/packet_capture.py
from scapy.all import AsyncSniffer, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from collections import deque
import threading
import time

class PacketCapture:
    def __init__(self, packet_queue, packet_limit=10000, filter_str="", interface=None):
        self.packet_queue = packet_queue
        self.packet_limit = packet_limit
        self.filter_str = filter_str
        self.interface = interface
        self.sniffer = None
        self.captured_packets = deque(maxlen=packet_limit)
        self.capture_lock = threading.Lock()
        self.is_capturing = False
        self.capture_stats = {
            'start_time': None,
            'packet_count': 0,
            'protocols': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        }

    def start(self):
        """Start packet capture in background thread"""
        if self.is_capturing:
            return False
        self.capture_stats['start_time'] = time.time()
        self.capture_stats['packet_count'] = 0
        self.capture_stats['protocols'] = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        try:
            sniffer_args = {
                'prn': self._packet_handler,
                'store': False
            }
            if self.filter_str:
                sniffer_args['filter'] = self.filter_str
            if self.interface:
                sniffer_args['iface'] = self.interface
            self.sniffer = AsyncSniffer(**sniffer_args)
            self.sniffer.start()
            self.is_capturing = True
            return True
        except Exception as e:
            print(f"Error starting sniffer: {e}")
            self.is_capturing = False
            return False

    def stop(self):
        """Stop packet capture"""
        if self.is_capturing and self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                print(f"Error stopping sniffer: {e}")
            self.is_capturing = False
            return True
        return False

    def _packet_handler(self, packet):
        """Process each captured packet"""
        print("DEBUG: Packet captured")  # Debug print to verify packet capture
        with self.capture_lock:
            self.captured_packets.append(packet)
            self.packet_queue.put(packet)
            self.capture_stats['packet_count'] += 1
            self._update_protocol_stats(packet)

    def _update_protocol_stats(self, packet):
        """Update protocol statistics"""
        if packet.haslayer(TCP):
            self.capture_stats['protocols']['TCP'] += 1
        elif packet.haslayer(UDP):
            self.capture_stats['protocols']['UDP'] += 1
        elif packet.haslayer(ICMP):
            self.capture_stats['protocols']['ICMP'] += 1
        else:
            self.capture_stats['protocols']['Other'] += 1

    def get_capture_stats(self):
        """Return current capture statistics"""
        return self.capture_stats.copy()

    def get_packets(self):
        """Return captured packets"""
        with self.capture_lock:
            return list(self.captured_packets)
