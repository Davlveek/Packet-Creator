import sys 
from PyQt5 import QtWidgets, QtGui
from PyQt5.QtCore import Qt
import PacketCreatorDesign
import os
import netifaces
from scapy.all import *

protocol = 0 # 0 - TCP, 1 - UDP, 2 - ICMP
protocolIP = 0 # 0 - IP, 1 - IPv6

packets = []
ipoptions = []
tcpoptions = []

def form_ethernet(self):
    part2 = Ether()
    # Source MAC
    srcMAC = self.SrcMAC.text()
    if srcMAC != "":
        part2.src = srcMAC
    # Destination MAC
    destMAC = self.DestMAC.text()
    if destMAC != "":
        part2.dst = destMAC
    # EtherType
    EtherType = self.EtherType.text()
    if EtherType != "":
        part2.type = int(EtherType, 0)
    return part2

def form_ipv4(self):
    part3 = IP()
    # Version
    version = self.versionIP.text()
    if version != "":
        part3.version = int(version)
    # IHL
    ihl = self.IHL.text()
    if ihl != "":
        part3.ihl = int(ihl)
    # tos
    tos = self.dscpIP.text()
    if tos != "":
        part3.tos = int(tos, 0)
    # Length
    len = self.lenIP.text()
    if len != "":
        part3.len = int(len)
    # ID
    id = self.idIP.text()
    if id != "":
        part3.id = int(id)
    # Flags
    flags = self.flagsIP.text()
    if flags != "":
        part3.flags = int(flags)
    # Fragment Offset
    offset = self.offsetIP.text()
    if offset != "":
        part3.frag = int(offset)
    # TTL
    ttl = self.TTL.text()
    if ttl != "":
        part3.ttl = int(ttl)
    # Protocol
    protocol = self.protocolIP.text()
    if protocol != "":
        part3.proto = protocol
    # Checksum    
    chksum = self.checkIP.text()
    if chksum != "":
        part3.chksum = int(chksum, 0)
    # Source IP
    src = self.srcIP.text()
    if src != "":
        part3.src = src
    # Destination IP
    dest = self.destIP.text()
    if dest != "":
        part3.dst = dest
    # Option  
    if self.nooptIP.isChecked():
        return part3
    else:
        part3.options = ipoptions 
    return part3

def form_ipv6(self):
    part3 = IPv6()
    # Version
    version = self.verIPv6.text()
    if version != "":
        part3.version = int(version)
    # Traffic Class
    tc = self.tcIPv6.text()
    if tc != "":
        part3.tc = int(tc, 0)
    # Flow Label
    fl = self.flIPv6.text()
    if fl != "":
        part3.fl = int(fl, 0)
    # Payload Length
    pl = self.payIPv6.text()
    if pl != "":
        part3.plen = int(pl)
    # Next Header
    nh = self.nhIPv6.text()
    if nh != "":
        part3.nh = int(nh)
    # Hop Limit
    hp = self.hlIPv6.text()
    if hp != "":
        part3.hlim = int(hp)
    # Source Address
    src = self.srcIPv6.text()
    if src != "":
        part3.src = src
    # Destination Address
    dst = self.destIPv6.text()
    if dst != "":
        part3.dst = dst
    return part3

def form_udp(self):
    part4 = UDP()
    # Source Port
    src = self.SrcUDP.text()
    if src != "":
        part4.sport = int(src)
    # Destination Port
    dest = self.DestUDP.text()
    if dest != "":
        part4.dport = int(dest)
    # Length
    len = self.lenUDP.text()
    if len != "":
        part4.len = int(len)
    # Checksum
    check = self.checkUDP.text()
    if check != "":
        part4.chksum = int(check, 0)
    return part4

def form_tcp(self):
    part4 = TCP()
    # Source Port
    src = self.SrcTCP.text()
    if src != "":
        part4.sport = int(src)
    # Destination Port
    dest = self.DestTCP.text()
    if dest != "":
        part4.dport = int(dest)
    # Sequence Number
    sqn = self.snTCP.text()
    if sqn != "":
        part4.seq = int(sqn)
    # Ack Number
    ack = self.ackTCP.text()
    if sqn != "":
        part4.ack = int(ack)
    # Data Offset
    dataofs = self.offsetTCP.text()
    if dataofs != "":
        part4.dataofs = int(dataofs)
    # Reserved
    res = self.reserTCP.text()
    if res != "":
        part4.reserved = int(res)
    # Flags
    flags = self.flagsTCP.text()
    if flags != "":
        part4.flags = int(flags, 0)
    # Window
    window = self.winTCP.text()
    if window != "":
        part4.window = int(window)
    # Checksum
    check = self.checkSum.text()
    if check != "":
        part4.chksum = int(check, 0)
    # Urgent Pointer
    urg = self.urgTCP.text()
    if urg != "":
        part4.urgptr = int(urg)
    # Option
    if self.nooptTCP.isChecked():
        return part4
    else:
        part4.options = tcpoptions 
    return part4

def form_icmp(self):
    part4 = ICMP()
    # Type
    typ = self.comboBox.currentText()
    if typ == "Echo Reply":
        part4.type = 0
    elif typ == "Echo Request":
        part4.type = 8
    # Code 
    code = self.codeICMP.text()
    if code != "":
        part4.code = int(code)
    # Checksum
    check = self.checkICMP.text()
    if check != "":
        part4.chksum = int(check, 0)
    # Identifier
    id = self.idICMP.text()
    if id != "":
        part4.id = int(id)
    # Sequence Number
    seq = self.snICMP.text()
    if seq != "":
        part4.seq = int(seq)
    return part4

def add_optIP(self):
    temp = IPOption()
    # Copy 
    if self.copyIP.isChecked():
        temp.copy_flag = 1
    else:
        temp.copy_flag = 0
    # Class
    optclass = self.classIP.text()
    if optclass != "":
        temp.optclass = int(optclass)
    # Number
    num = self.numIP.text()
    if num != "":
        temp.option = int(num)
    # Length
    len = self.lenoptIP.text()
    if len != "":
        temp.length = int(len)
    # Value
    val = self.valopIP.text()
    if val != "":
        temp.value = int(val)
    ipoptions.append(temp)

def add_optTCP(self):
    # Kind 
    kind = self.kindTCP.text()
    if kind == "":
        kind = "0"
    # Length
    len = self.lenoptTCP.text()
    if len == "":
        len = "0"
    tcpoptions.append((int(kind), int(len)))

class PacketCreatorApp(QtWidgets.QMainWindow, PacketCreatorDesign.Ui_PacketCreator):
    def __init__(self):
        super().__init__()
        self.setupUi(self)  # Desing init
        self.tabWidget.currentChanged.connect(self.tab_protocol_changed)
        self.tabWidget_2.currentChanged.connect(self.tab_ip_changed)
        self.SendButton.clicked.connect(self.send_protocol)
        self.addoptIP.clicked.connect(self.add_optionIP)
        self.nooptIP.stateChanged.connect(self.noooptIP_changed)
        self.nooptTCP.stateChanged.connect(self.nooptTCP_changed)
        self.addoptTCP.clicked.connect(self.add_optionTCP)
        self.clearopIP.clicked.connect(self.clear_optionIP)
        self.clearopTCP.clicked.connect(self.clear_optionTCP)
        self.addPacket.clicked.connect(self.add_packet)
        self.clearPackets.clicked.connect(self.clear_packets)
        # Clear buttons
        self.clearTCP.clicked.connect(self.clear_tcp)
        self.clearIP.clicked.connect(self.clear_ipv4)
        self.clearUDP.clicked.connect(self.clear_udp)
        self.clearIPv6.clicked.connect(self.clear_ipv6)
        self.clearICMP.clicked.connect(self.clear_icmp)
        # Set buttons
        self.setIP.clicked.connect(self.set_ipv4) 
        self.setTCP.clicked.connect(self.set_tcp)
        self.setUDP.clicked.connect(self.set_udp)
        self.setIPv6.clicked.connect(self.set_ipv6)
        self.setICMP.clicked.connect(self.set_icmp)
        self.interface_2.addItems(netifaces.interfaces()) # Set net interfaces

    def clear_optionTCP(self):
        tcpoptions.clear()

    def clear_optionIP(self):
        ipoptions.clear()

    def add_optionTCP(self):
        add_optTCP(self)

    def nooptTCP_changed(self, state):
        if state == Qt.Checked:
            self.kindTCP.setDisabled(True)
            self.lenoptTCP.setDisabled(True)
            self.addoptTCP.setEnabled(False)
        else:
            self.kindTCP.setDisabled(False)
            self.lenoptTCP.setDisabled(False)    
            self.addoptTCP.setEnabled(True)

    def noooptIP_changed(self, state):
        if state == Qt.Checked:
            self.lenoptIP.setDisabled(True)
            self.classIP.setDisabled(True)
            self.numIP.setDisabled(True)
            self.valopIP.setDisabled(True)
            self.copyIP.setEnabled(False)
            self.addoptIP.setEnabled(False)
        else:
            self.lenoptIP.setDisabled(False)
            self.classIP.setDisabled(False)
            self.numIP.setDisabled(False)
            self.valopIP.setDisabled(False)
            self.copyIP.setEnabled(True)
            self.addoptIP.setEnabled(True)

    def add_optionIP(self):
        add_optIP(self)

    def set_icmp(self):
        self.codeICMP.setText("0")
        self.checkICMP.setText("0xffff")
        self.idICMP.setText("0")
        self.snICMP.setText("0")

    def clear_icmp(self):
        self.codeICMP.setText("")
        self.checkICMP.setText("")
        self.idICMP.setText("")
        self.snICMP.setText("")

    def set_ipv6(self):
        self.verIPv6.setText("6")
        self.tcIPv6.setText("0x0")
        self.flIPv6.setText("0x0")
        self.payIPv6.setText("24")
        self.nhIPv6.setText("6")
        self.hlIPv6.setText("64")
        self.srcIPv6.setText("::1")
        self.destIPv6.setText("::1")

    def clear_ipv6(self):
        self.verIPv6.setText("")
        self.tcIPv6.setText("")
        self.flIPv6.setText("")
        self.payIPv6.setText("")
        self.nhIPv6.setText("")
        self.hlIPv6.setText("")
        self.srcIPv6.setText("")
        self.destIPv6.setText("")

    def clear_udp(self):
        self.SrcUDP.setText("")
        self.DestUDP.setText("")
        self.lenUDP.setText("")
        self.checkUDP.setText("")

    def set_udp(self):
        self.SrcUDP.setText("9000")
        self.DestUDP.setText("9001")
        self.lenUDP.setText("12")
        self.checkUDP.setText("0x13e9")

    def clear_ipv4(self):
        self.versionIP.setText("")
        self.IHL.setText("")
        self.dscpIP.setText("")
        self.lenIP.setText("")
        self.idIP.setText("")
        self.flagsIP.setText("")
        self.offsetIP.setText("")
        self.TTL.setText("")
        self.protocolIP.setText("")
        self.checkIP.setText("")
        self.srcIP.setText("")
        self.destIP.setText("")
        self.nooptIP.setChecked(False)

    def set_ipv4(self):
        self.versionIP.setText("4")
        self.IHL.setText("5")
        self.dscpIP.setText("0x0")
        self.lenIP.setText("32")
        self.idIP.setText("1")
        self.flagsIP.setText("")
        self.offsetIP.setText("0")
        self.TTL.setText("64")
        self.protocolIP.setText("tcp")
        self.checkIP.setText("0x7cca")
        self.srcIP.setText("127.0.0.1")
        self.destIP.setText("127.0.0.1")
        self.nooptIP.setChecked(True)

    def set_tcp(self):
        self.SrcTCP.setText("9000")
        self.DestTCP.setText("9001")
        self.snTCP.setText("0")
        self.ackTCP.setText("0")
        self.offsetTCP.setText("5")
        self.reserTCP.setText("")
        self.flagsTCP.setText("0x002")
        self.winTCP.setText("8192")
        self.checkSum.setText("0xe9de")
        self.urgTCP.setText("0")
        self.nooptTCP.setChecked(True)

    def clear_tcp(self):
        self.SrcTCP.setText("")
        self.DestTCP.setText("")
        self.snTCP.setText("")
        self.ackTCP.setText("")
        self.offsetTCP.setText("")
        self.reserTCP.setText("")
        self.flagsTCP.setText("")
        self.winTCP.setText("")
        self.checkSum.setText("")
        self.urgTCP.setText("")
        self.nooptTCP.setChecked(False)

    def clear_packets(self):
        packets.clear()
        ipoptions.clear()
        tcpoptions.clear()

    def add_packet(self):
        # Forming Ethernet
        part2 = form_ethernet(self)
        # Forming IP
        if protocolIP:
            part3 = form_ipv6(self)
        else:
            part3 = form_ipv4(self)
        # Forming Protocols
        if protocol == 0:
            part4 = form_tcp(self)
        elif protocol == 1:
            part4 = form_udp(self)
        elif protocol == 2:
            part4 = form_icmp(self)

        data = self.textEdit.toPlainText()
        packet = part3 / part4 / data # remember part2
        #packet.show()
        packets.append(packet)

    def send_protocol(self):
        if len(packets) == 0:
            QtWidgets.QMessageBox.about(self, "Info", "Packets is empty")
            return
        iface = self.interface_2.currentText()
        for packet in packets:
            send(packet, iface=iface)         

    def tab_ip_changed(self, i):
        global protocolIP
        protocolIP = i

    def tab_protocol_changed(self, i):
        global protocol
        protocol = i
       

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = PacketCreatorApp()
    window.show()  
    app.exec_()  # Start app   

if __name__ == '__main__': 
    main()  