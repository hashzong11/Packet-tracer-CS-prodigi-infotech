# deepnet/utils.py
import platform
import sys
import os
import logging
from datetime import datetime

def setup_logger():
    """Configure logging for DeepNet"""
    logger = logging.getLogger('DeepNet')
    logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def get_os_compatibility():
    """Check OS compatibility and required dependencies"""
    system = platform.system()
    if system not in ['Windows', 'Linux']:
        raise OSError(f"Unsupported operating system: {system}")
    return system

def validate_root():
    """Check for administrative privileges"""
    if platform.system() == 'Windows':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.getuid() == 0

def timestamp_to_str(timestamp):
    """Convert timestamp to human-readable format"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')

def format_hexdump(payload, bytes_per_line=16):
    """Create hexdump representation of payload"""
    if not payload:
        return ""
    
    hexdump = []
    for i in range(0, len(payload), bytes_per_line):
        chunk = payload[i:i+bytes_per_line]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        hexdump.append(f"{i:04x}  {hex_str.ljust(bytes_per_line*3)}  {ascii_str}")
    return '\n'.join(hexdump)

def display_warning():
    """Display ethical use warning"""
    print("\n" + "="*70)
    print("WARNING: ETHICAL AND LEGAL CONSIDERATIONS".center(70))
    print("="*70)
    print("- This tool should only be used on networks you own or have explicit")
    print("  permission to monitor")
    print("- Unauthorized network scanning may violate federal and local laws")
    print("- You are solely responsible for proper use of this tool")
    print("- Educational purposes only - no warranty provided")
    print("="*70 + "\n")