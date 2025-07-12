# deepnet/cli.py
import argparse
import signal
import sys
import queue
from packet_capture import PacketCapture
from packet_analyzer import PacketAnalyzer
from utils import display_warning, setup_logger

logger = setup_logger()

capture = None  # Keep as module-level for signal handler

def list_interfaces():
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception as e:
        logger.error(f"Could not list interfaces: {e}")
        return []

def signal_handler(sig, frame):
    """Handle Ctrl+C interrupt"""
    print("\nCapture stopped by user.")
    global capture
    if capture and capture.is_capturing:
        capture.stop()
    sys.exit(0)

def display_packet(packet):
    """Display packet information in CLI"""
    analysis = PacketAnalyzer.analyze_packet(packet)
    src = analysis['src_ip'] or '-'
    dst = analysis['dst_ip'] or '-'
    sport = analysis['src_port'] or '-'
    dport = analysis['dst_port'] or '-'
    proto = analysis['protocol'] or '-'
    print(f"[{analysis['timestamp']}] {src}:{sport}  {dst}:{dport} {proto} {analysis['size']} bytes")
    print(f"  Info: {analysis['info']}")
    if analysis['hexdump']:
        print("  Payload:")
        print(analysis['hexdump'])

def start_capture(interface, filter_str, packet_limit):
    """Start packet capture process"""
    global capture
    packet_queue = queue.Queue()
    capture = PacketCapture(packet_queue, packet_limit, filter_str, interface=interface)
    signal.signal(signal.SIGINT, signal_handler)
    print(f"Starting capture on interface {interface}...")
    started = capture.start()
    if not started:
        print("Failed to start packet capture. Check your permissions and interface name.")
        sys.exit(1)
    try:
        while True:
            try:
                packet = packet_queue.get(timeout=1)
                display_packet(packet)
            except queue.Empty:
                continue
    except KeyboardInterrupt:
        capture.stop()
    except Exception as e:
        logger.error(f"Error during capture: {e}")
        capture.stop()
        sys.exit(1)

def main():
    """Main CLI entry point"""
    display_warning()
    parser = argparse.ArgumentParser(
        description="DeepNet CLI Packet Analyzer",
        epilog="Example: python cli.py -i eth0 -f 'tcp port 80'"
    )
    parser.add_argument("-i", "--interface", required=False,
                        help="Network interface to capture on (leave blank to list interfaces)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter expression")
    parser.add_argument("-l", "--limit", type=int, default=1000,
                        help="Maximum packets to capture")
    args = parser.parse_args()

    # Detect or prompt for interface
    if not args.interface:
        interfaces = list_interfaces()
        if not interfaces:
            print("No network interfaces found. Exiting.")
            sys.exit(1)
        print("Available network interfaces:")
        for idx, iface in enumerate(interfaces):
            print(f"  {idx+1}. {iface}")
        try:
            choice = int(input("Select interface number: "))
            if 1 <= choice <= len(interfaces):
                args.interface = interfaces[choice-1]
            else:
                print("Invalid selection. Exiting.")
                sys.exit(1)
        except Exception:
            print("Invalid input. Exiting.")
            sys.exit(1)

    # Set the interface
    from scapy.all import conf
    conf.iface = args.interface
    start_capture(args.interface, args.filter, args.limit)

if __name__ == "__main__":
    main()
