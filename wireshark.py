from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import *
from winpcapy import WinPcapUtils
from winpcapy import WinPcap
from winpcapy import WinPcapDevices
import dpkt, socket, time, binascii
from threading import Thread

def bindigits(n, bits):
    s = bin(n & int("1"*bits, 2))[2:]
    return ("{0:0>%s}" % (bits)).format(s)

def bytes_to_hex(data):
    return str(binascii.b2a_hex(data))[2: -1]

def enet_ntoa(data):
    addr = bytes_to_hex(data)
    result = addr[0: 2]
    for i in range(2, len(addr), 2):
        result += ":"
        result += addr[i: i + 2]
    return result

class wireshark_GUI():

    device_list = WinPcapDevices.list_devices()
    device = "*Ethernet*"
    capture_flag = False
    packets_num = 0
    packets_captured = {}

    def __init__(self):
        self.app = QApplication([])

        self.wireshark = QMainWindow()
        self.wireshark.resize(960, 670)
        self.wireshark.setWindowTitle('wireshark')

        self.start_button = QPushButton('START', self.wireshark)
        self.start_button.setObjectName(u"start_button")
        self.start_button.setGeometry(QRect(280, 20, 80, 20))

        self.device_combo = QComboBox(self.wireshark)
        self.device_combo.setObjectName(u"device_combo")
        self.device_combo.setGeometry(QRect(20, 20, 250, 20))

        self.packets_list = QListWidget(self.wireshark)
        self.packets_list.setObjectName(u"packets_list")
        self.packets_list.setGeometry(QRect(20, 60, 920, 250))

        self.layer_browser = QTextBrowser(self.wireshark)
        self.layer_browser.setObjectName(u"layer_browser")
        self.layer_browser.setGeometry(QRect(20, 330, 920, 150))

        self.hex_browser = QTextBrowser(self.wireshark)
        self.hex_browser.setObjectName(u"hex_browser")
        self.hex_browser.setGeometry(QRect(20, 500, 920, 150))
        
        self.start_button.clicked.connect(self.sniff)

        for i in self.device_list.values():
            self.device_combo.addItem(i)
        self.device_combo.currentIndexChanged.connect(self.change_device)

        self.packets_list.currentItemChanged.connect(self.packet_display)

    def capture(self):
        def packet_callback(win_pcap, param, header, pkt_data):
            eth = dpkt.ethernet.Ethernet(pkt_data)
            types = eth.type

            if types == 0x0800: # IPV4
                try:
                    struct = {}
                    ip = eth.data
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)
                    if type(ip.data)  == dpkt.tcp.TCP:
                        struct['type'] = 'TCP'
                    elif type(ip.data) == dpkt.udp.UDP:
                        struct['type'] = 'UDP'
                    else:
                        struct['type'] = 'IPV4'
                    struct['src'] = src
                    struct['dst'] = dst
                    struct['length'] = len(pkt_data)
                    # struct['hex'] = bytes_to_hex(pkt_data)
                    struct['data'] = pkt_data
                    # global packets_num
                    self.packets_num += 1
                    self.packets_captured[self.packets_num] = struct
                    display_text = str(self.packets_num) + "\t" + str(struct['length']) + "\t" + struct['type'] + "\t" + struct['src'] + " -> " + struct['dst']
                    self.packets_list.addItem(display_text)
                except:
                    pass
            elif types == 0x86dd: # IPV6
                try:
                    struct = {}
                    ip6 = eth.data
                    src = socket.inet_ntop(socket.AF_INET6, ip6.src)
                    dst = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                    struct['type'] = 'IPV6'
                    struct['src'] = src
                    struct['dst'] = dst
                    struct['length'] = len(pkt_data)
                    # struct['hex'] = bytes_to_hex(pkt_data)
                    struct['data'] = pkt_data
                    # global packets_num
                    self.packets_num += 1
                    self.packets_captured[self.packets_num] = struct
                    display_text = str(self.packets_num) + "\t" + str(struct['length']) + "\t" + struct['type'] + "\t" + struct['src'] + " -> " + struct['dst']
                    self.packets_list.addItem(display_text)
                except:
                    pass
            elif types == 0x0806: # ARP
                try:
                    struct = {}
                    src = enet_ntoa(eth.src)
                    dst = enet_ntoa(eth.dst)
                    struct['type'] = 'ARP'
                    struct['src'] = src
                    struct['dst'] = dst
                    struct['length'] = len(pkt_data)
                    # struct['hex'] = bytes_to_hex(pkt_data)
                    struct['data'] = pkt_data
                    # global packets_num
                    self.packets_num += 1
                    self.packets_captured[self.packets_num] = struct
                    display_text = str(self.packets_num) + "\t" + str(struct['length']) + "\t" + struct['type'] + "\t" + struct['src'] + " -> " + struct['dst']
                    self.packets_list.addItem(display_text)
                except:
                    pass

            if self.capture_flag == False:
                capture.stop()

        self.packets_list.clear()
        self.packets_captured.clear()
        self.packets_num = 0
        device_name, desc = WinPcapDevices.get_matching_device(self.device)
        if device_name is not None:
            with WinPcap(device_name) as capture:
                capture.run(callback=packet_callback)

    def layer_browser_display(self, data):
        text = ""
        eth = dpkt.ethernet.Ethernet(data)
        text += "Ethernet Layer:\n"
        text += "    Destination: " + enet_ntoa(eth.dst) + "\n"
        text += "    Source: " + enet_ntoa(eth.src) + "\n"
        text += "    Type: " + hex(eth.type) + "\n"
        if eth.type == 0x0800: # IPV4
            ip = eth.data
            text += "Internet Protocol Version 4:\n"
            text += "    Version: " + str(ip.v) + "\n"
            text += "    Header Length: " + str(ip.hl) + "\n"
            text += "    Type of Service: " + str(ip.tos) + "\n"
            text += "    Total Length: " + str(ip.len) + "\n"
            text += "    Identification: " + str(hex(ip.id)) + " (" + str(ip.id) + ")\n"
            text += "    Flags: \n"
            text += "        _*** **** **** **** " + str(bindigits(ip.rf, 1)) + "\t\t: Reserved bit\n"
            text += "        *_** **** **** **** " + str(bindigits(ip.df, 1)) + "\t\t: Don't fragment\n"
            text += "        **_* **** **** **** " + str(bindigits(ip.mf, 1)) + "\t\t: More fragments\n"
            text += "        ***_ ____ ____ ____ " + str(bindigits(ip.offset, 13)) + "\t: Fragment Offset\n"
            text += "    Time to Live: " + str(ip.ttl) + "\n"
            text += "    Protocol: " + str(ip.p) + "\n"
            text += "    Header Checksum: " + str(hex(ip.sum)) + "\n"
            text += "    Source Address: " + socket.inet_ntoa(ip.src) + "\n"
            text += "    Destination Address: " + socket.inet_ntoa(ip.dst) + "\n"
            if type(ip.data)  == dpkt.tcp.TCP:
                tcp = ip.data
                text += "Transmission Control Protocol:\n"
                text += "    Source Port: " + str(tcp.sport) + "\n"
                text += "    Destination Port: " + str(tcp.dport) + "\n"
                text += "    Sequence Number: " + str(tcp.seq) + "\n"
                text += "    Acknowledgment Number: " + str(tcp.ack) + "\n"
                text += "    Header Length: " + str(tcp.off) + " (" + str(tcp.off * 4) + " bytes)\n"
                text += "    Flags: \n"
                text += "        ___* **** **** " + str(bindigits(tcp.flags, 12)[0: 3]) + "\t: Reserved\n"
                text += "        ***_ **** **** " + str(bindigits(tcp.flags, 12)[3]) + "\t: Nonce\n"
                text += "        **** _*** **** " + str(bindigits(tcp.flags, 12)[4]) + "\t: Congestion Window Reduced\n"
                text += "        **** *_** **** " + str(bindigits(tcp.flags, 12)[5]) + "\t: ECN-Echo\n"
                text += "        **** **_* **** " + str(bindigits(tcp.flags, 12)[6]) + "\t: Urgent\n"
                text += "        **** ***_ **** " + str(bindigits(tcp.flags, 12)[7]) + "\t: Acknowledgment\n"
                text += "        **** **** _*** " + str(bindigits(tcp.flags, 12)[8]) + "\t: Push\n"
                text += "        **** **** *_** " + str(bindigits(tcp.flags, 12)[9]) + "\t: Rest\n"
                text += "        **** **** **_* " + str(bindigits(tcp.flags, 12)[10]) + "\t: Syn\n"
                text += "        **** **** ***_ " + str(bindigits(tcp.flags, 12)[11]) + "\t: Fin\n"
                text += "    Window: " + str(tcp.win) + "\n"
                text += "    Checksum: " + str(hex(tcp.sum)) + "\n"
                text += "    Urgent Pointer: " + str(tcp.urp) + "\n"
                text += "TCP Data:\n"
                text += "    Protocol Data: " + bytes_to_hex(bytes(tcp.data)) + "\n"
            elif type(ip.data) == dpkt.udp.UDP:
                udp = ip.data
                text += "User Datagram Protocol:\n"
                text += "    Source Port: " + str(udp.sport) + "\n"
                text += "    Destination Port: " + str(udp.dport) + "\n"
                text += "    Length: " + str(udp.ulen) + "\n"
                text += "    Checksum: " + str(hex(udp.sum)) + "\n"
                text += "UDP Data:\n"
                text += "    Protocol Data: " + bytes_to_hex(bytes(udp.data)) + "\n"
            else:
                text += "Unknow Protocol:\n"
                text += "    Protocol Data: " + bytes_to_hex(bytes(ip.data)) + "\n"
        elif eth.type == 0x86dd: # IPV6
            ip6 = eth.data
            text += "Internet Protocol Version 6:\n"
            text += "    Version: " + str(ip6.v) + "\n"
            text += "    Traffic Class: " + str(ip6.fc) + "\n"
            text += "    Flow Label: " + str(ip6.flow) + "\n"
            text += "    Payload Length: " + str(ip6.plen) + "\n"
            text += "    Next Header: " + str(ip6.nxt) + "\n"
            text += "    Hop Limit: " + str(ip6.hlim) + "\n"
            text += "    Source Address: " + socket.inet_ntop(socket.AF_INET6, ip6.src) + "\n"
            text += "    Destination Address: " + socket.inet_ntop(socket.AF_INET6, ip6.dst) + "\n"
            text += "Unknow Protocol:\n"
            text += "    Protocol Data: " + bytes_to_hex(bytes(ip6.data)) + "\n"
        elif eth.type == 0x0806: # ARP
            arp = eth.data
            text += "Address Resolution Protocol:\n"
            text += "    Hardware type: " + str(arp.hrd) + "\n"
            text += "    Protocol type: " + str(hex(arp.pro)) + "\n"
            text += "    Hardware size: " + str(arp.hln) + "\n"
            text += "    Protocol size: " + str(arp.pln) + "\n"
            text += "    Opcode: " + str(arp.op) + "\n"
            text += "    Sender MAC address: " + enet_ntoa(arp.sha) + "\n"
            text += "    Sender IP address: " + socket.inet_ntoa(arp.spa) + "\n"
            text += "    Target MAC address: " + enet_ntoa(arp.tha) + "\n"
            text += "    Target IP address: " + socket.inet_ntoa(arp.tpa) + "\n"
        self.layer_browser.setPlainText(text)

    def hex_browser_display(self, data):
        text = ""
        hex = bytes_to_hex(data)
        for i in range(0, len(hex), 2):
            text += hex[i: i + 2] + " "
            if (i + 2) % 16 == 0:
                text += "\t"
            if (i + 2) % 32 == 0:
                text += "\n"
        self.hex_browser.setPlainText(text.upper())

    def sniff(self):
        if self.capture_flag == False: # start sniffer
            self.capture_flag = True
            thread_capture = Thread(target=self.capture, args=())
            thread_capture.start()
            self.start_button.setText("STOP")
        elif self.capture_flag == True: # stop sniffer
            self.capture_flag = False
            self.start_button.setText("START")

    def change_device(self):
        self.device = self.device_combo.currentText()

    def packet_display(self):
        self.layer_browser.clearHistory()
        self.hex_browser.clearHistory()

        while(True):
            try:
                data = self.packets_captured[self.packets_list.currentRow() + 1]['data']
                self.layer_browser_display(data)
                self.hex_browser_display(data)
                break
            except:
                pass

wireshark = wireshark_GUI()
wireshark.wireshark.show()
wireshark.app.exec()