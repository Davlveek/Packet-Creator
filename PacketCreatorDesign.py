# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'PacketCreator.ui'
#
# Created by: PyQt5 UI code generator 5.13.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_PacketCreator(object):
    def setupUi(self, PacketCreator):
        PacketCreator.setObjectName("PacketCreator")
        PacketCreator.resize(1100, 537)
        self.centralwidget = QtWidgets.QWidget(PacketCreator)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 0, 561, 391))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.DestTCP = QtWidgets.QLineEdit(self.tab)
        self.DestTCP.setGeometry(QtCore.QRect(290, 30, 241, 25))
        self.DestTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.DestTCP.setObjectName("DestTCP")
        self.label_21 = QtWidgets.QLabel(self.tab)
        self.label_21.setGeometry(QtCore.QRect(340, 10, 121, 17))
        self.label_21.setObjectName("label_21")
        self.SrcTCP = QtWidgets.QLineEdit(self.tab)
        self.SrcTCP.setGeometry(QtCore.QRect(40, 30, 241, 25))
        self.SrcTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.SrcTCP.setObjectName("SrcTCP")
        self.label_22 = QtWidgets.QLabel(self.tab)
        self.label_22.setGeometry(QtCore.QRect(130, 10, 91, 17))
        self.label_22.setObjectName("label_22")
        self.label_25 = QtWidgets.QLabel(self.tab)
        self.label_25.setGeometry(QtCore.QRect(220, 60, 121, 17))
        self.label_25.setObjectName("label_25")
        self.snTCP = QtWidgets.QLineEdit(self.tab)
        self.snTCP.setGeometry(QtCore.QRect(40, 80, 491, 25))
        self.snTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.snTCP.setObjectName("snTCP")
        self.label_26 = QtWidgets.QLabel(self.tab)
        self.label_26.setGeometry(QtCore.QRect(190, 110, 181, 17))
        self.label_26.setObjectName("label_26")
        self.ackTCP = QtWidgets.QLineEdit(self.tab)
        self.ackTCP.setGeometry(QtCore.QRect(40, 130, 491, 25))
        self.ackTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.ackTCP.setObjectName("ackTCP")
        self.label_27 = QtWidgets.QLabel(self.tab)
        self.label_27.setGeometry(QtCore.QRect(40, 160, 81, 17))
        self.label_27.setObjectName("label_27")
        self.offsetTCP = QtWidgets.QLineEdit(self.tab)
        self.offsetTCP.setGeometry(QtCore.QRect(40, 180, 81, 25))
        self.offsetTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.offsetTCP.setObjectName("offsetTCP")
        self.label_28 = QtWidgets.QLabel(self.tab)
        self.label_28.setGeometry(QtCore.QRect(130, 160, 71, 17))
        self.label_28.setObjectName("label_28")
        self.reserTCP = QtWidgets.QLineEdit(self.tab)
        self.reserTCP.setGeometry(QtCore.QRect(130, 180, 61, 25))
        self.reserTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.reserTCP.setObjectName("reserTCP")
        self.label_29 = QtWidgets.QLabel(self.tab)
        self.label_29.setGeometry(QtCore.QRect(200, 160, 81, 17))
        self.label_29.setObjectName("label_29")
        self.label_30 = QtWidgets.QLabel(self.tab)
        self.label_30.setGeometry(QtCore.QRect(370, 160, 61, 17))
        self.label_30.setObjectName("label_30")
        self.winTCP = QtWidgets.QLineEdit(self.tab)
        self.winTCP.setGeometry(QtCore.QRect(290, 180, 241, 25))
        self.winTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.winTCP.setObjectName("winTCP")
        self.flagsTCP = QtWidgets.QLineEdit(self.tab)
        self.flagsTCP.setGeometry(QtCore.QRect(200, 180, 81, 25))
        self.flagsTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.flagsTCP.setObjectName("flagsTCP")
        self.label_31 = QtWidgets.QLabel(self.tab)
        self.label_31.setGeometry(QtCore.QRect(110, 210, 111, 17))
        self.label_31.setObjectName("label_31")
        self.checkSum = QtWidgets.QLineEdit(self.tab)
        self.checkSum.setGeometry(QtCore.QRect(40, 230, 241, 25))
        self.checkSum.setAlignment(QtCore.Qt.AlignCenter)
        self.checkSum.setObjectName("checkSum")
        self.label_32 = QtWidgets.QLabel(self.tab)
        self.label_32.setGeometry(QtCore.QRect(360, 210, 111, 17))
        self.label_32.setObjectName("label_32")
        self.urgTCP = QtWidgets.QLineEdit(self.tab)
        self.urgTCP.setGeometry(QtCore.QRect(290, 230, 241, 25))
        self.urgTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.urgTCP.setObjectName("urgTCP")
        self.clearTCP = QtWidgets.QPushButton(self.tab)
        self.clearTCP.setGeometry(QtCore.QRect(40, 320, 89, 25))
        self.clearTCP.setObjectName("clearTCP")
        self.setTCP = QtWidgets.QPushButton(self.tab)
        self.setTCP.setGeometry(QtCore.QRect(140, 320, 71, 25))
        self.setTCP.setObjectName("setTCP")
        self.nooptTCP = QtWidgets.QCheckBox(self.tab)
        self.nooptTCP.setGeometry(QtCore.QRect(220, 320, 92, 23))
        self.nooptTCP.setObjectName("nooptTCP")
        self.kindTCP = QtWidgets.QLineEdit(self.tab)
        self.kindTCP.setGeometry(QtCore.QRect(110, 280, 113, 25))
        self.kindTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.kindTCP.setObjectName("kindTCP")
        self.label_51 = QtWidgets.QLabel(self.tab)
        self.label_51.setGeometry(QtCore.QRect(40, 280, 61, 17))
        self.label_51.setObjectName("label_51")
        self.label_52 = QtWidgets.QLabel(self.tab)
        self.label_52.setGeometry(QtCore.QRect(150, 260, 31, 17))
        self.label_52.setObjectName("label_52")
        self.lenoptTCP = QtWidgets.QLineEdit(self.tab)
        self.lenoptTCP.setGeometry(QtCore.QRect(230, 280, 113, 25))
        self.lenoptTCP.setAlignment(QtCore.Qt.AlignCenter)
        self.lenoptTCP.setObjectName("lenoptTCP")
        self.label_53 = QtWidgets.QLabel(self.tab)
        self.label_53.setGeometry(QtCore.QRect(260, 260, 67, 17))
        self.label_53.setObjectName("label_53")
        self.addoptTCP = QtWidgets.QPushButton(self.tab)
        self.addoptTCP.setGeometry(QtCore.QRect(360, 280, 89, 25))
        self.addoptTCP.setObjectName("addoptTCP")
        self.clearopTCP = QtWidgets.QPushButton(self.tab)
        self.clearopTCP.setGeometry(QtCore.QRect(460, 280, 89, 25))
        self.clearopTCP.setObjectName("clearopTCP")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.SrcUDP = QtWidgets.QLineEdit(self.tab_2)
        self.SrcUDP.setGeometry(QtCore.QRect(90, 80, 181, 25))
        self.SrcUDP.setAlignment(QtCore.Qt.AlignCenter)
        self.SrcUDP.setObjectName("SrcUDP")
        self.DestUDP = QtWidgets.QLineEdit(self.tab_2)
        self.DestUDP.setGeometry(QtCore.QRect(280, 80, 181, 25))
        self.DestUDP.setAlignment(QtCore.Qt.AlignCenter)
        self.DestUDP.setObjectName("DestUDP")
        self.lenUDP = QtWidgets.QLineEdit(self.tab_2)
        self.lenUDP.setGeometry(QtCore.QRect(90, 130, 181, 25))
        self.lenUDP.setAlignment(QtCore.Qt.AlignCenter)
        self.lenUDP.setObjectName("lenUDP")
        self.checkUDP = QtWidgets.QLineEdit(self.tab_2)
        self.checkUDP.setGeometry(QtCore.QRect(280, 130, 181, 25))
        self.checkUDP.setAlignment(QtCore.Qt.AlignCenter)
        self.checkUDP.setObjectName("checkUDP")
        self.label_6 = QtWidgets.QLabel(self.tab_2)
        self.label_6.setGeometry(QtCore.QRect(140, 60, 91, 17))
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(self.tab_2)
        self.label_7.setGeometry(QtCore.QRect(310, 60, 121, 17))
        self.label_7.setObjectName("label_7")
        self.label_8 = QtWidgets.QLabel(self.tab_2)
        self.label_8.setGeometry(QtCore.QRect(150, 110, 51, 17))
        self.label_8.setObjectName("label_8")
        self.label_9 = QtWidgets.QLabel(self.tab_2)
        self.label_9.setGeometry(QtCore.QRect(310, 110, 111, 17))
        self.label_9.setObjectName("label_9")
        self.clearUDP = QtWidgets.QPushButton(self.tab_2)
        self.clearUDP.setGeometry(QtCore.QRect(40, 320, 89, 25))
        self.clearUDP.setObjectName("clearUDP")
        self.setUDP = QtWidgets.QPushButton(self.tab_2)
        self.setUDP.setGeometry(QtCore.QRect(140, 320, 89, 25))
        self.setUDP.setObjectName("setUDP")
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.label_41 = QtWidgets.QLabel(self.tab_3)
        self.label_41.setGeometry(QtCore.QRect(90, 100, 41, 17))
        self.label_41.setObjectName("label_41")
        self.codeICMP = QtWidgets.QLineEdit(self.tab_3)
        self.codeICMP.setGeometry(QtCore.QRect(170, 120, 111, 25))
        self.codeICMP.setObjectName("codeICMP")
        self.checkICMP = QtWidgets.QLineEdit(self.tab_3)
        self.checkICMP.setGeometry(QtCore.QRect(290, 120, 231, 25))
        self.checkICMP.setObjectName("checkICMP")
        self.label_42 = QtWidgets.QLabel(self.tab_3)
        self.label_42.setGeometry(QtCore.QRect(210, 100, 41, 17))
        self.label_42.setObjectName("label_42")
        self.label_43 = QtWidgets.QLabel(self.tab_3)
        self.label_43.setGeometry(QtCore.QRect(340, 100, 111, 17))
        self.label_43.setObjectName("label_43")
        self.comboBox = QtWidgets.QComboBox(self.tab_3)
        self.comboBox.setGeometry(QtCore.QRect(50, 120, 111, 25))
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.label_44 = QtWidgets.QLabel(self.tab_3)
        self.label_44.setGeometry(QtCore.QRect(130, 150, 67, 17))
        self.label_44.setObjectName("label_44")
        self.idICMP = QtWidgets.QLineEdit(self.tab_3)
        self.idICMP.setGeometry(QtCore.QRect(50, 170, 231, 25))
        self.idICMP.setObjectName("idICMP")
        self.label_45 = QtWidgets.QLabel(self.tab_3)
        self.label_45.setGeometry(QtCore.QRect(340, 150, 131, 17))
        self.label_45.setObjectName("label_45")
        self.snICMP = QtWidgets.QLineEdit(self.tab_3)
        self.snICMP.setGeometry(QtCore.QRect(290, 170, 231, 25))
        self.snICMP.setObjectName("snICMP")
        self.clearICMP = QtWidgets.QPushButton(self.tab_3)
        self.clearICMP.setGeometry(QtCore.QRect(40, 320, 89, 25))
        self.clearICMP.setObjectName("clearICMP")
        self.setICMP = QtWidgets.QPushButton(self.tab_3)
        self.setICMP.setGeometry(QtCore.QRect(140, 320, 89, 25))
        self.setICMP.setObjectName("setICMP")
        self.tabWidget.addTab(self.tab_3, "")
        self.DestMAC = QtWidgets.QLineEdit(self.centralwidget)
        self.DestMAC.setGeometry(QtCore.QRect(10, 460, 211, 25))
        self.DestMAC.setAlignment(QtCore.Qt.AlignCenter)
        self.DestMAC.setObjectName("DestMAC")
        self.SrcMAC = QtWidgets.QLineEdit(self.centralwidget)
        self.SrcMAC.setGeometry(QtCore.QRect(10, 430, 211, 25))
        self.SrcMAC.setAlignment(QtCore.Qt.AlignCenter)
        self.SrcMAC.setObjectName("SrcMAC")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(80, 410, 61, 21))
        self.label.setObjectName("label")
        self.interface_2 = QtWidgets.QComboBox(self.centralwidget)
        self.interface_2.setGeometry(QtCore.QRect(370, 430, 191, 25))
        self.interface_2.setObjectName("interface_2")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(430, 410, 67, 17))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(230, 460, 121, 17))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(230, 430, 91, 17))
        self.label_4.setObjectName("label_4")
        self.EtherType = QtWidgets.QLineEdit(self.centralwidget)
        self.EtherType.setGeometry(QtCore.QRect(10, 490, 211, 25))
        self.EtherType.setAlignment(QtCore.Qt.AlignCenter)
        self.EtherType.setObjectName("EtherType")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(230, 490, 111, 17))
        self.label_5.setObjectName("label_5")
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setGeometry(QtCore.QRect(350, 400, 20, 141))
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.line_2 = QtWidgets.QFrame(self.centralwidget)
        self.line_2.setGeometry(QtCore.QRect(0, 390, 1101, 16))
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.line_3 = QtWidgets.QFrame(self.centralwidget)
        self.line_3.setGeometry(QtCore.QRect(570, -20, 20, 561))
        self.line_3.setFrameShape(QtWidgets.QFrame.VLine)
        self.line_3.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_3.setObjectName("line_3")
        self.SendButton = QtWidgets.QPushButton(self.centralwidget)
        self.SendButton.setGeometry(QtCore.QRect(640, 500, 121, 21))
        self.SendButton.setObjectName("SendButton")
        self.tabWidget_2 = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget_2.setGeometry(QtCore.QRect(580, 0, 501, 391))
        self.tabWidget_2.setObjectName("tabWidget_2")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setObjectName("tab_4")
        self.label_23 = QtWidgets.QLabel(self.tab_4)
        self.label_23.setGeometry(QtCore.QRect(160, 10, 61, 17))
        self.label_23.setObjectName("label_23")
        self.IHL = QtWidgets.QLineEdit(self.tab_4)
        self.IHL.setGeometry(QtCore.QRect(80, 30, 61, 25))
        self.IHL.setAlignment(QtCore.Qt.AlignCenter)
        self.IHL.setObjectName("IHL")
        self.dscpIP = QtWidgets.QLineEdit(self.tab_4)
        self.dscpIP.setGeometry(QtCore.QRect(150, 30, 81, 25))
        self.dscpIP.setAlignment(QtCore.Qt.AlignCenter)
        self.dscpIP.setObjectName("dscpIP")
        self.label_11 = QtWidgets.QLabel(self.tab_4)
        self.label_11.setGeometry(QtCore.QRect(10, 10, 61, 17))
        self.label_11.setObjectName("label_11")
        self.label_12 = QtWidgets.QLabel(self.tab_4)
        self.label_12.setGeometry(QtCore.QRect(100, 10, 21, 17))
        self.label_12.setObjectName("label_12")
        self.versionIP = QtWidgets.QLineEdit(self.tab_4)
        self.versionIP.setGeometry(QtCore.QRect(10, 30, 61, 25))
        self.versionIP.setAlignment(QtCore.Qt.AlignCenter)
        self.versionIP.setObjectName("versionIP")
        self.lenIP = QtWidgets.QLineEdit(self.tab_4)
        self.lenIP.setGeometry(QtCore.QRect(240, 30, 241, 25))
        self.lenIP.setAlignment(QtCore.Qt.AlignCenter)
        self.lenIP.setObjectName("lenIP")
        self.label_13 = QtWidgets.QLabel(self.tab_4)
        self.label_13.setGeometry(QtCore.QRect(330, 10, 51, 17))
        self.label_13.setObjectName("label_13")
        self.idIP = QtWidgets.QLineEdit(self.tab_4)
        self.idIP.setGeometry(QtCore.QRect(10, 80, 221, 25))
        self.idIP.setAlignment(QtCore.Qt.AlignCenter)
        self.idIP.setObjectName("idIP")
        self.label_14 = QtWidgets.QLabel(self.tab_4)
        self.label_14.setGeometry(QtCore.QRect(70, 60, 91, 17))
        self.label_14.setObjectName("label_14")
        self.offsetIP = QtWidgets.QLineEdit(self.tab_4)
        self.offsetIP.setGeometry(QtCore.QRect(310, 80, 171, 25))
        self.offsetIP.setAlignment(QtCore.Qt.AlignCenter)
        self.offsetIP.setObjectName("offsetIP")
        self.label_15 = QtWidgets.QLabel(self.tab_4)
        self.label_15.setGeometry(QtCore.QRect(330, 60, 121, 17))
        self.label_15.setObjectName("label_15")
        self.flagsIP = QtWidgets.QLineEdit(self.tab_4)
        self.flagsIP.setGeometry(QtCore.QRect(240, 80, 61, 25))
        self.flagsIP.setAlignment(QtCore.Qt.AlignCenter)
        self.flagsIP.setObjectName("flagsIP")
        self.label_24 = QtWidgets.QLabel(self.tab_4)
        self.label_24.setGeometry(QtCore.QRect(250, 60, 41, 17))
        self.label_24.setObjectName("label_24")
        self.TTL = QtWidgets.QLineEdit(self.tab_4)
        self.TTL.setGeometry(QtCore.QRect(10, 130, 101, 25))
        self.TTL.setAlignment(QtCore.Qt.AlignCenter)
        self.TTL.setObjectName("TTL")
        self.label_16 = QtWidgets.QLabel(self.tab_4)
        self.label_16.setGeometry(QtCore.QRect(50, 110, 31, 17))
        self.label_16.setObjectName("label_16")
        self.protocolIP = QtWidgets.QLineEdit(self.tab_4)
        self.protocolIP.setGeometry(QtCore.QRect(120, 130, 111, 25))
        self.protocolIP.setAlignment(QtCore.Qt.AlignCenter)
        self.protocolIP.setObjectName("protocolIP")
        self.label_17 = QtWidgets.QLabel(self.tab_4)
        self.label_17.setGeometry(QtCore.QRect(150, 110, 61, 17))
        self.label_17.setObjectName("label_17")
        self.checkIP = QtWidgets.QLineEdit(self.tab_4)
        self.checkIP.setGeometry(QtCore.QRect(240, 130, 241, 25))
        self.checkIP.setText("")
        self.checkIP.setAlignment(QtCore.Qt.AlignCenter)
        self.checkIP.setReadOnly(False)
        self.checkIP.setObjectName("checkIP")
        self.label_18 = QtWidgets.QLabel(self.tab_4)
        self.label_18.setGeometry(QtCore.QRect(300, 110, 111, 17))
        self.label_18.setObjectName("label_18")
        self.label_19 = QtWidgets.QLabel(self.tab_4)
        self.label_19.setGeometry(QtCore.QRect(190, 160, 111, 17))
        self.label_19.setObjectName("label_19")
        self.srcIP = QtWidgets.QLineEdit(self.tab_4)
        self.srcIP.setGeometry(QtCore.QRect(10, 180, 471, 25))
        self.srcIP.setInputMask("")
        self.srcIP.setText("")
        self.srcIP.setAlignment(QtCore.Qt.AlignCenter)
        self.srcIP.setPlaceholderText("")
        self.srcIP.setObjectName("srcIP")
        self.label_20 = QtWidgets.QLabel(self.tab_4)
        self.label_20.setGeometry(QtCore.QRect(180, 210, 141, 17))
        self.label_20.setObjectName("label_20")
        self.destIP = QtWidgets.QLineEdit(self.tab_4)
        self.destIP.setGeometry(QtCore.QRect(10, 230, 471, 25))
        self.destIP.setAlignment(QtCore.Qt.AlignCenter)
        self.destIP.setObjectName("destIP")
        self.clearIP = QtWidgets.QPushButton(self.tab_4)
        self.clearIP.setGeometry(QtCore.QRect(10, 320, 89, 25))
        self.clearIP.setObjectName("clearIP")
        self.setIP = QtWidgets.QPushButton(self.tab_4)
        self.setIP.setGeometry(QtCore.QRect(110, 320, 71, 25))
        self.setIP.setObjectName("setIP")
        self.copyIP = QtWidgets.QCheckBox(self.tab_4)
        self.copyIP.setGeometry(QtCore.QRect(80, 280, 61, 23))
        self.copyIP.setObjectName("copyIP")
        self.nooptIP = QtWidgets.QCheckBox(self.tab_4)
        self.nooptIP.setGeometry(QtCore.QRect(190, 320, 92, 23))
        self.nooptIP.setObjectName("nooptIP")
        self.classIP = QtWidgets.QLineEdit(self.tab_4)
        self.classIP.setGeometry(QtCore.QRect(140, 280, 51, 25))
        self.classIP.setAlignment(QtCore.Qt.AlignCenter)
        self.classIP.setObjectName("classIP")
        self.label_46 = QtWidgets.QLabel(self.tab_4)
        self.label_46.setGeometry(QtCore.QRect(150, 260, 41, 17))
        self.label_46.setObjectName("label_46")
        self.numIP = QtWidgets.QLineEdit(self.tab_4)
        self.numIP.setGeometry(QtCore.QRect(200, 280, 61, 25))
        self.numIP.setAlignment(QtCore.Qt.AlignCenter)
        self.numIP.setObjectName("numIP")
        self.label_47 = QtWidgets.QLabel(self.tab_4)
        self.label_47.setGeometry(QtCore.QRect(200, 260, 61, 17))
        self.label_47.setObjectName("label_47")
        self.lenoptIP = QtWidgets.QLineEdit(self.tab_4)
        self.lenoptIP.setGeometry(QtCore.QRect(270, 280, 51, 25))
        self.lenoptIP.setAlignment(QtCore.Qt.AlignCenter)
        self.lenoptIP.setObjectName("lenoptIP")
        self.label_48 = QtWidgets.QLabel(self.tab_4)
        self.label_48.setGeometry(QtCore.QRect(270, 260, 51, 17))
        self.label_48.setObjectName("label_48")
        self.valopIP = QtWidgets.QLineEdit(self.tab_4)
        self.valopIP.setGeometry(QtCore.QRect(330, 280, 51, 25))
        self.valopIP.setAlignment(QtCore.Qt.AlignCenter)
        self.valopIP.setObjectName("valopIP")
        self.label_49 = QtWidgets.QLabel(self.tab_4)
        self.label_49.setGeometry(QtCore.QRect(340, 260, 41, 17))
        self.label_49.setObjectName("label_49")
        self.addoptIP = QtWidgets.QPushButton(self.tab_4)
        self.addoptIP.setGeometry(QtCore.QRect(390, 280, 89, 25))
        self.addoptIP.setObjectName("addoptIP")
        self.label_50 = QtWidgets.QLabel(self.tab_4)
        self.label_50.setGeometry(QtCore.QRect(10, 280, 67, 17))
        self.label_50.setObjectName("label_50")
        self.clearopIP = QtWidgets.QPushButton(self.tab_4)
        self.clearopIP.setGeometry(QtCore.QRect(390, 320, 89, 25))
        self.clearopIP.setObjectName("clearopIP")
        self.tabWidget_2.addTab(self.tab_4, "")
        self.tab_5 = QtWidgets.QWidget()
        self.tab_5.setObjectName("tab_5")
        self.label_33 = QtWidgets.QLabel(self.tab_5)
        self.label_33.setGeometry(QtCore.QRect(10, 10, 51, 17))
        self.label_33.setObjectName("label_33")
        self.verIPv6 = QtWidgets.QLineEdit(self.tab_5)
        self.verIPv6.setGeometry(QtCore.QRect(10, 30, 61, 25))
        self.verIPv6.setAlignment(QtCore.Qt.AlignCenter)
        self.verIPv6.setObjectName("verIPv6")
        self.label_34 = QtWidgets.QLabel(self.tab_5)
        self.label_34.setGeometry(QtCore.QRect(70, 10, 121, 17))
        self.label_34.setObjectName("label_34")
        self.tcIPv6 = QtWidgets.QLineEdit(self.tab_5)
        self.tcIPv6.setGeometry(QtCore.QRect(80, 30, 101, 25))
        self.tcIPv6.setAlignment(QtCore.Qt.AlignCenter)
        self.tcIPv6.setObjectName("tcIPv6")
        self.label_35 = QtWidgets.QLabel(self.tab_5)
        self.label_35.setGeometry(QtCore.QRect(270, 10, 121, 17))
        self.label_35.setObjectName("label_35")
        self.flIPv6 = QtWidgets.QLineEdit(self.tab_5)
        self.flIPv6.setGeometry(QtCore.QRect(190, 30, 291, 25))
        self.flIPv6.setAlignment(QtCore.Qt.AlignCenter)
        self.flIPv6.setObjectName("flIPv6")
        self.label_36 = QtWidgets.QLabel(self.tab_5)
        self.label_36.setGeometry(QtCore.QRect(80, 60, 111, 17))
        self.label_36.setObjectName("label_36")
        self.payIPv6 = QtWidgets.QLineEdit(self.tab_5)
        self.payIPv6.setGeometry(QtCore.QRect(10, 80, 231, 25))
        self.payIPv6.setAlignment(QtCore.Qt.AlignCenter)
        self.payIPv6.setObjectName("payIPv6")
        self.label_37 = QtWidgets.QLabel(self.tab_5)
        self.label_37.setGeometry(QtCore.QRect(260, 60, 91, 17))
        self.label_37.setObjectName("label_37")
        self.nhIPv6 = QtWidgets.QLineEdit(self.tab_5)
        self.nhIPv6.setGeometry(QtCore.QRect(250, 80, 113, 25))
        self.nhIPv6.setAlignment(QtCore.Qt.AlignCenter)
        self.nhIPv6.setObjectName("nhIPv6")
        self.label_38 = QtWidgets.QLabel(self.tab_5)
        self.label_38.setGeometry(QtCore.QRect(390, 60, 71, 17))
        self.label_38.setObjectName("label_38")
        self.hlIPv6 = QtWidgets.QLineEdit(self.tab_5)
        self.hlIPv6.setGeometry(QtCore.QRect(370, 80, 113, 25))
        self.hlIPv6.setAlignment(QtCore.Qt.AlignCenter)
        self.hlIPv6.setObjectName("hlIPv6")
        self.label_39 = QtWidgets.QLabel(self.tab_5)
        self.label_39.setGeometry(QtCore.QRect(190, 110, 111, 17))
        self.label_39.setObjectName("label_39")
        self.label_40 = QtWidgets.QLabel(self.tab_5)
        self.label_40.setGeometry(QtCore.QRect(180, 160, 151, 17))
        self.label_40.setObjectName("label_40")
        self.srcIPv6 = QtWidgets.QLineEdit(self.tab_5)
        self.srcIPv6.setGeometry(QtCore.QRect(10, 130, 471, 25))
        self.srcIPv6.setAlignment(QtCore.Qt.AlignCenter)
        self.srcIPv6.setObjectName("srcIPv6")
        self.destIPv6 = QtWidgets.QLineEdit(self.tab_5)
        self.destIPv6.setGeometry(QtCore.QRect(10, 180, 471, 25))
        self.destIPv6.setAlignment(QtCore.Qt.AlignCenter)
        self.destIPv6.setObjectName("destIPv6")
        self.clearIPv6 = QtWidgets.QPushButton(self.tab_5)
        self.clearIPv6.setGeometry(QtCore.QRect(10, 320, 89, 25))
        self.clearIPv6.setObjectName("clearIPv6")
        self.setIPv6 = QtWidgets.QPushButton(self.tab_5)
        self.setIPv6.setGeometry(QtCore.QRect(110, 320, 91, 25))
        self.setIPv6.setObjectName("setIPv6")
        self.tabWidget_2.addTab(self.tab_5, "")
        self.textEdit = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit.setGeometry(QtCore.QRect(600, 420, 471, 70))
        self.textEdit.setObjectName("textEdit")
        self.label_10 = QtWidgets.QLabel(self.centralwidget)
        self.label_10.setGeometry(QtCore.QRect(820, 400, 41, 17))
        self.label_10.setObjectName("label_10")
        self.line_4 = QtWidgets.QFrame(self.centralwidget)
        self.line_4.setGeometry(QtCore.QRect(0, 530, 1101, 20))
        self.line_4.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_4.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_4.setObjectName("line_4")
        self.addPacket = QtWidgets.QPushButton(self.centralwidget)
        self.addPacket.setGeometry(QtCore.QRect(770, 500, 121, 21))
        self.addPacket.setObjectName("addPacket")
        self.clearPackets = QtWidgets.QPushButton(self.centralwidget)
        self.clearPackets.setGeometry(QtCore.QRect(900, 500, 121, 21))
        self.clearPackets.setObjectName("clearPackets")
        PacketCreator.setCentralWidget(self.centralwidget)

        self.retranslateUi(PacketCreator)
        self.tabWidget.setCurrentIndex(0)
        self.tabWidget_2.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(PacketCreator)

    def retranslateUi(self, PacketCreator):
        _translate = QtCore.QCoreApplication.translate
        PacketCreator.setWindowTitle(_translate("PacketCreator", "PacketCreator"))
        self.label_21.setText(_translate("PacketCreator", "Destination Port"))
        self.label_22.setText(_translate("PacketCreator", "Source Port"))
        self.label_25.setText(_translate("PacketCreator", "Sequence number"))
        self.label_26.setText(_translate("PacketCreator", "Acknowledgment Number"))
        self.label_27.setText(_translate("PacketCreator", "Data Offset"))
        self.label_28.setText(_translate("PacketCreator", "Reserved"))
        self.label_29.setText(_translate("PacketCreator", "Flags (hex)"))
        self.label_30.setText(_translate("PacketCreator", "Window"))
        self.label_31.setText(_translate("PacketCreator", "Checksum (hex)"))
        self.label_32.setText(_translate("PacketCreator", "Urgent Pointer"))
        self.clearTCP.setText(_translate("PacketCreator", "Clear TCP"))
        self.setTCP.setText(_translate("PacketCreator", "Set TCP"))
        self.nooptTCP.setText(_translate("PacketCreator", "No Option"))
        self.label_51.setText(_translate("PacketCreator", "Options:"))
        self.label_52.setText(_translate("PacketCreator", "Kind"))
        self.label_53.setText(_translate("PacketCreator", "Length"))
        self.addoptTCP.setText(_translate("PacketCreator", "Add Option"))
        self.clearopTCP.setText(_translate("PacketCreator", "Clear Option"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("PacketCreator", "TCP"))
        self.label_6.setText(_translate("PacketCreator", "Source Port"))
        self.label_7.setText(_translate("PacketCreator", "Destination Port"))
        self.label_8.setText(_translate("PacketCreator", "Length"))
        self.label_9.setText(_translate("PacketCreator", "Checksum (hex)"))
        self.clearUDP.setText(_translate("PacketCreator", "Clear UDP"))
        self.setUDP.setText(_translate("PacketCreator", "Set UDP"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("PacketCreator", "UDP"))
        self.label_41.setText(_translate("PacketCreator", "Type"))
        self.label_42.setText(_translate("PacketCreator", "Code"))
        self.label_43.setText(_translate("PacketCreator", "Checksum (hex)"))
        self.comboBox.setItemText(0, _translate("PacketCreator", "Echo Reply"))
        self.comboBox.setItemText(1, _translate("PacketCreator", "Echo Request"))
        self.label_44.setText(_translate("PacketCreator", "Identifier"))
        self.label_45.setText(_translate("PacketCreator", "Sequence Number"))
        self.clearICMP.setText(_translate("PacketCreator", "Clear ICMP"))
        self.setICMP.setText(_translate("PacketCreator", "Set ICMP"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("PacketCreator", "ICMP"))
        self.label.setText(_translate("PacketCreator", "Ethernet"))
        self.label_2.setText(_translate("PacketCreator", "Interface"))
        self.label_3.setText(_translate("PacketCreator", "Destination MAC"))
        self.label_4.setText(_translate("PacketCreator", "Source MAC"))
        self.label_5.setText(_translate("PacketCreator", "EtherType (hex)"))
        self.SendButton.setText(_translate("PacketCreator", "Send"))
        self.label_23.setText(_translate("PacketCreator", "tos (hex)"))
        self.label_11.setText(_translate("PacketCreator", "Version"))
        self.label_12.setText(_translate("PacketCreator", "IHL"))
        self.label_13.setText(_translate("PacketCreator", "Length"))
        self.label_14.setText(_translate("PacketCreator", "Identification"))
        self.label_15.setText(_translate("PacketCreator", "Fragment Offset"))
        self.label_24.setText(_translate("PacketCreator", "Flags"))
        self.label_16.setText(_translate("PacketCreator", "TTL"))
        self.label_17.setText(_translate("PacketCreator", "Protocol"))
        self.label_18.setText(_translate("PacketCreator", "Checksum (hex)"))
        self.label_19.setText(_translate("PacketCreator", "Source Address"))
        self.label_20.setText(_translate("PacketCreator", "Destination Address"))
        self.clearIP.setText(_translate("PacketCreator", "Clear IPv4"))
        self.setIP.setText(_translate("PacketCreator", "Set IPv4"))
        self.copyIP.setText(_translate("PacketCreator", "Copy"))
        self.nooptIP.setText(_translate("PacketCreator", "No Option"))
        self.label_46.setText(_translate("PacketCreator", "Class"))
        self.label_47.setText(_translate("PacketCreator", "Number"))
        self.label_48.setText(_translate("PacketCreator", "Length"))
        self.label_49.setText(_translate("PacketCreator", "Value"))
        self.addoptIP.setText(_translate("PacketCreator", "Add Option"))
        self.label_50.setText(_translate("PacketCreator", "Options:"))
        self.clearopIP.setText(_translate("PacketCreator", "Clear Option"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_4), _translate("PacketCreator", "IPv4"))
        self.label_33.setText(_translate("PacketCreator", "Version"))
        self.label_34.setText(_translate("PacketCreator", "Traffic Class (hex)"))
        self.label_35.setText(_translate("PacketCreator", "Flow Label (hex)"))
        self.label_36.setText(_translate("PacketCreator", "Payload Length"))
        self.label_37.setText(_translate("PacketCreator", "Next Header"))
        self.label_38.setText(_translate("PacketCreator", "Hop Limit"))
        self.label_39.setText(_translate("PacketCreator", "Source Address"))
        self.label_40.setText(_translate("PacketCreator", "Destination Address"))
        self.clearIPv6.setText(_translate("PacketCreator", "Clear IPv6"))
        self.setIPv6.setText(_translate("PacketCreator", "Set IPv6"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_5), _translate("PacketCreator", "IPv6"))
        self.label_10.setText(_translate("PacketCreator", "Data"))
        self.addPacket.setText(_translate("PacketCreator", "Add Packet"))
        self.clearPackets.setText(_translate("PacketCreator", "Clear Packets"))
