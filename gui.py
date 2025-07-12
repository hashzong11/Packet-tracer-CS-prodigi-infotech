# deepnet/gui.py
import sys
import queue
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableView, QPushButton, QLabel, QComboBox, QLineEdit,
                             QTextEdit, QSplitter, QHeaderView, QMessageBox, QSystemTrayIcon)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QAbstractTableModel, QTimer, QModelIndex
from PyQt5.QtGui import QFont, QColor, QIcon
from packet_capture import PacketCapture
from packet_analyzer import PacketAnalyzer
from utils import display_warning, format_hexdump, timestamp_to_str

class CaptureThread(QThread):
    packet_captured = pyqtSignal(object)
    
    def __init__(self, interface, filter_str):
        super().__init__()
        self.interface = interface
        self.filter_str = filter_str
        self.packet_queue = queue.Queue()
        self.capture = None
        self.running = False
        
    def run(self):
        self.running = True
        self.capture = PacketCapture(self.packet_queue, filter_str=self.filter_str, interface=self.interface)
        
        # Set the interface
        from scapy.all import conf
        conf.iface = self.interface
        
        started = self.capture.start()
        if not started:
            return
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=0.5)
                self.packet_captured.emit(packet)
            except queue.Empty:
                if not self.running:
                    break
    
    def stop(self):
        self.running = False
        if self.capture:
            self.capture.stop()

class PacketTableModel(QAbstractTableModel):
    headers = ["Time", "Source", "Destination", "Protocol", "Length", "Info"]
    
    def __init__(self):
        super().__init__()
        self.packets = []
        self.analysis_data = []
        
    def rowCount(self, parent=None):
        return len(self.packets)
    
    def columnCount(self, parent=None):
        return len(self.headers)
    
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.analysis_data):
            return None
            
        analysis = self.analysis_data[index.row()]
        col = index.column()
        
        if role == Qt.DisplayRole:
            if col == 0:  # Time
                return analysis.get('timestamp', '-')
            elif col == 1:  # Source
                port_str = f":{analysis.get('src_port', '')}" if analysis.get('src_port') else ""
                return f"{analysis.get('src_ip', '-')}{port_str}"
            elif col == 2:  # Destination
                port_str = f":{analysis.get('dst_port', '')}" if analysis.get('dst_port') else ""
                return f"{analysis.get('dst_ip', '-')}{port_str}"
            elif col == 3:  # Protocol
                return analysis.get('protocol', '-')
            elif col == 4:  # Length
                return str(analysis.get('size', '-'))
            elif col == 5:  # Info
                return analysis.get('info', '-')
                
        elif role == Qt.UserRole:  # Full packet data
            return analysis
            
        return None
    
    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None
    
    def add_packet(self, packet):
        self.beginInsertRows(QModelIndex(), len(self.packets), len(self.packets))
        self.packets.append(packet)
        analysis = PacketAnalyzer.analyze_packet(packet)
        self.analysis_data.append(analysis)
        self.endInsertRows()
    
    def clear(self):
        self.beginResetModel()
        self.packets = []
        self.analysis_data = []
        self.endResetModel()

class DeepNetGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DeepNet Packet Analyzer")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set application icon
        try:
            self.setWindowIcon(QIcon("deepnet_icon.png"))
        except:
            pass
            
        self.init_ui()
        self.capture_thread = None
        self.display_warning()
        
    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Control Panel
        control_layout = QHBoxLayout()
        
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(150)
        self.populate_interfaces()
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("BPF Filter (e.g., tcp port 80)")
        self.filter_edit.setMinimumWidth(250)
        
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.toggle_capture)
        
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_packets)
        
        control_layout.addWidget(QLabel("Interface:"))
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(QLabel("Filter:"))
        control_layout.addWidget(self.filter_edit)
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addStretch()
        
        # Packet Table
        self.table_view = QTableView()
        self.table_view.setSelectionBehavior(QTableView.SelectRows)
        self.table_view.setSelectionMode(QTableView.SingleSelection)
        self.table_view.doubleClicked.connect(self.show_packet_details)
        self.table_model = PacketTableModel()
        self.table_view.setModel(self.table_model)
        
        # Set column widths
        header = self.table_view.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Source
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Destination
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Protocol
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(5, QHeaderView.Stretch)  # Info
        
        # Packet Details
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Courier New", 10))
        
        # Hex View
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont(QFont("Courier New", 10))
        
        # Splitter for details and hex
        detail_splitter = QSplitter(Qt.Vertical)
        detail_splitter.addWidget(self.details_text)
        detail_splitter.addWidget(self.hex_text)
        detail_splitter.setSizes([300, 200])
        
        # Main splitter
        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(self.table_view)
        main_splitter.addWidget(detail_splitter)
        main_splitter.setSizes([400, 200])
        
        # Status Bar
        self.status_bar = self.statusBar()
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
        # Assemble main layout
        main_layout.addLayout(control_layout)
        main_layout.addWidget(main_splitter)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000)
        
    def populate_interfaces(self):
        """Populate network interfaces dropdown"""
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            if interfaces:
                self.interface_combo.addItems(interfaces)
            else:
                self.interface_combo.addItem('No interfaces found')
                QMessageBox.critical(self, "Error", "No network interfaces found. Please check your network adapters.")
        except Exception as e:
            self.interface_combo.addItem('No interfaces found')
            QMessageBox.critical(self, "Error", f"Could not list interfaces: {e}")
        
    def toggle_capture(self):
        """Start or pause capture"""
        if self.capture_thread and self.capture_thread.isRunning():
            self.stop_capture()
        else:
            self.start_capture()
            
    def start_capture(self):
        """Start packet capture"""
        interface = self.interface_combo.currentText()
        filter_str = self.filter_edit.text()
        
        if not interface or interface == 'No interfaces found':
            QMessageBox.warning(self, "Error", "Please select a network interface")
            return
        
        self.capture_thread = CaptureThread(interface, filter_str)
        self.capture_thread.packet_captured.connect(self.add_packet)
        self.capture_thread.start()
        
        self.start_btn.setText("Pause Capture")
        self.stop_btn.setEnabled(True)
        self.status_label.setText(f"Capturing on {interface}...")
        
    def stop_capture(self):
        """Stop packet capture"""
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
        
        self.start_btn.setText("Start Capture")
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Capture stopped")
        
    def clear_packets(self):
        """Clear captured packets"""
        self.table_model.clear()
        self.details_text.clear()
        self.hex_text.clear()
        
    def add_packet(self, packet):
        """Add new packet to table"""
        self.table_model.add_packet(packet)
        self.table_view.scrollToBottom()  # Ensure the latest packet is visible
        
    def show_packet_details(self, index):
        """Display detailed packet information"""
        analysis = index.data(Qt.UserRole)
        if not analysis:
            self.details_text.setText("No details available")
            self.hex_text.setText("")
            return
        # Build details text
        details = f"Time: {analysis.get('timestamp', '-')}\n"
        details += f"Source: {analysis.get('src_ip', '-')}"
        if analysis.get('src_port'):
            details += f":{analysis.get('src_port')}"
        details += "\n"
        details += f"Destination: {analysis.get('dst_ip', '-')}"
        if analysis.get('dst_port'):
            details += f":{analysis.get('dst_port')}"
        details += "\n"
        details += f"Protocol: {analysis.get('protocol', '-')}\n"
        details += f"Length: {analysis.get('size', '-')} bytes\n"
        details += f"Info: {analysis.get('info', '-')}\n"
        self.details_text.setText(details)
        # Show hexdump if available
        if analysis.get('hexdump'):
            self.hex_text.setText(analysis['hexdump'])
        else:
            self.hex_text.setText("No payload data")
        
    def update_stats(self):
        """Update status bar with capture statistics"""
        if self.capture_thread and self.capture_thread.capture:
            stats = self.capture_thread.capture.get_capture_stats()
            if stats['start_time']:
                elapsed = time.time() - stats['start_time']
                stats_text = (f"Packets: {stats['packet_count']} | "
                             f"TCP: {stats['protocols']['TCP']} | "
                             f"UDP: {stats['protocols']['UDP']} | "
                             f"ICMP: {stats['protocols']['ICMP']} | "
                             f"Other: {stats['protocols']['Other']} | "
                             f"Elapsed: {elapsed:.1f}s")
                self.status_label.setText(stats_text)
        
    def display_warning(self):
        """Show ethical use warning using utils.display_warning"""
        display_warning()
        QMessageBox.information(self, "Ethical Use Warning",
            "WARNING: ETHICAL AND LEGAL CONSIDERATIONS\n\n"
            "1. Use only on networks you own or have permission to monitor\n"
            "2. Unauthorized scanning may violate laws\n"
            "3. Educational purposes only\n"
            "4. You are responsible for proper use of this tool\n\n"
            "By using DeepNet, you agree to use it ethically and legally.")
        
    def closeEvent(self, event):
        """Handle window close event"""
        self.stop_capture()
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # Modern style
    
    # Create and show main window
    window = DeepNetGUI()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
