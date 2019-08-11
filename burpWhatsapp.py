from burp import IBurpExtender, ITab
from javax.swing import JPanel, JTextArea, JTextField, JLabel, JButton, BorderFactory, SwingConstants
from java.awt import GridBagLayout, GridBagConstraints, BorderLayout, Color, Font

import json
import socket
import pickle
import os

class BurpExtender(IBurpExtender, ITab):
    socket_time_out = 3

    def registerExtenderCallbacks(self, callbacks):
        self.out = callbacks.getStdout()

        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WhatsApp Decoder")

        self.banner = JLabel("WHATSAPP DECRYPTION AND ENCRYPTION EXTENSION BY DIKLA BARDA, ROMAN ZAIKIN", SwingConstants.CENTER)
        self.banner.setFont(Font("Serif", Font.PLAIN, 17))
        self.banner.setBorder(BorderFactory.createLineBorder(Color.BLACK))

        self.statusConn = JLabel("CONNECTION STATUS:  ")
        self.statusConnField = JLabel("NOT CONNECTED")
        self.statusAct = JLabel("ACTION STATUS:      ")
        self.statusActField = JLabel("OK")

        self.ref = JLabel("Ref object:  ")
        self.refField = JTextField("", 80)
        self.refField.setToolTipText("Copy the Ref from burpsuit WebSocket, make sure that the parameter 'secret' is there and you copy only the 'ref' without the connection and other data, if not logout from your whatsapp web and login again.")

        self.privateKey = JLabel("Private Key:")
        self.privateKeyField = JTextField("", 80)
        self.privateKeyField.setToolTipText("Copy the private key list from your whatsapp web according to our blog post.")

        self.publicKey = JLabel("Public Key: ")
        self.publicKeyField = JTextField("", 80)
        self.publicKeyField.setToolTipText("Copy the public key list from your whatsapp web according to our blog post.")

        self.statusPanel1 = JPanel()
        self.statusPanel1.add(self.statusConn)
        self.statusPanel1.add(self.statusConnField)

        self.statusPanel2 = JPanel()
        self.statusPanel2.add(self.statusAct)
        self.statusPanel2.add(self.statusActField)

        self.privateKeyPanel = JPanel()
        self.privateKeyPanel.add(self.privateKey)
        self.privateKeyPanel.add(self.privateKeyField)

        self.publicKeyPanel = JPanel()
        self.publicKeyPanel.add(self.publicKey)
        self.publicKeyPanel.add(self.publicKeyField)

        self.refPanel = JPanel()
        self.refPanel.add(self.ref)
        self.refPanel.add(self.refField)

        self.messageField = JTextArea('["action", {"add": "relay"}, [{"message": {"conversation": "WhatsApp Protocol Decryption!"}, "participant": "97252XXXXXXX@s.whatsapp.net", "messageTimestamp": "1565193325", "key": {"fromMe": false, "remoteJid": "1310XXXXXXX-1565122127@g.us", "id": "78CECC5019E81B84B64ED2F6A57217AK"}, "status": "ERROR"}]]', 5, 90)
        self.messageField.setLineWrap(True)
        self.messageField.setToolTipText("Incoming traffic is from burp suite websocket, The outgoing traffic is the list from aesCbcEncrypt")

        self.messageTag = JLabel("Message Tag:")
        self.messageTagField = JTextField("", 80)
        self.messageTagField.setToolTipText("Copy the message tag from WebSocket it's the text until first ',' ")
        self.messageTagFieldButton = JButton("Update Tag", actionPerformed=self.performUpdateTag)

        self.whatsAppMessagesPanel = JPanel()
        self.whatsAppMessagesPanel.add(self.messageField)

        self.messageTagPanel = JPanel()
        self.messageTagPanel.add(self.messageTag)
        self.messageTagPanel.add(self.messageTagField)
        self.messageTagPanel.add(self.messageTagFieldButton)

        self.btnSave = JButton("Connect", actionPerformed=self.saveConfig)
        self.btnRestore = JButton("Clear", actionPerformed=self.clearConfig)

        self.grpConfig = JPanel()
        self.grpConfig.add(self.btnSave)
        self.grpConfig.add(self.btnRestore)

        self.btnIncoming = JButton("Incoming", actionPerformed=self.performAction)
        self.btnOutgoing = JButton("Outgoing", actionPerformed=self.performAction)

        self.btnEncrypt = JButton("Encrypt", actionPerformed=self.performAction)
        self.btnEncrypt.setEnabled(False)  # Can't send data without a direction

        self.btnDecrypt = JButton("Decrypt", actionPerformed=self.performAction)
        self.btnDecrypt.setEnabled(False)  # Can't send data without a direction

        self.btnCrypt = JPanel()
        self.btnCrypt.add(self.btnIncoming)
        self.btnCrypt.add(self.btnEncrypt)
        self.btnCrypt.add(self.btnDecrypt)
        self.btnCrypt.add(self.btnOutgoing)

        self.tab = JPanel()
        layout = GridBagLayout()
        self.tab.setLayout(layout)

        c = GridBagConstraints()

        c.ipadx = 0
        c.ipady = 0

        c.fill = GridBagConstraints.BOTH
        #c.weightx = 0 # gap between the x items
        #c.weighty = 0 # gap between the y items

        c.anchor = GridBagConstraints.NORTHWEST

        c.gridx = 0
        c.gridy = 0
        self.tab.add(self.banner, c)

        c.gridx = 0
        c.gridy = 1
        self.tab.add(self.refPanel, c)

        c.gridx = 0
        c.gridy = 2
        self.tab.add(self.privateKeyPanel, c)

        c.gridx = 0
        c.gridy = 3
        self.tab.add(self.publicKeyPanel, c)

        c.gridx = 0
        c.gridy = 4
        c.anchor = GridBagConstraints.CENTER
        self.tab.add(self.grpConfig, c)

        c.gridx = 0
        c.gridy = 5
        self.tab.add(self.whatsAppMessagesPanel, c)

        c.gridx = 0
        c.gridy = 6
        self.tab.add(self.messageTagPanel, c)

        c.gridx = 0
        c.gridy = 7
        self.tab.add(self.btnCrypt, c)

        c.gridx = 0
        c.gridy = 8
        self.tab.add(self.statusPanel1, c)

        c.gridx = 0
        c.gridy = 9
        self.tab.add(self.statusPanel2, c)

        # restore config
        self.restoreConfig()
        callbacks.addSuiteTab(self)

    def performUpdateTag(self, e=None):

        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.settimeout(self.socket_time_out)

        clientData = json.dumps({"action": "tagUpdate",
                                 "data": {
                                     "msg_tag": self.messageTagField.getText()
                                    }
                                 })

        self.client.sendto(clientData, ("127.0.0.1", 2912))
        self.client.close()

    def performAction(self, e=None):

        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.settimeout(self.socket_time_out)

        self.data = self.messageField.getText()

        eventSource = e.getSource()
        eventSource.setEnabled(False)

        # Incoming data
        if eventSource == self.btnIncoming:
            self.direction = "in"
            self.btnOutgoing.setEnabled(True)
            self.btnEncrypt.setEnabled(True)
            self.btnDecrypt.setEnabled(True)

        # Outgoing data
        elif eventSource == self.btnOutgoing:
            self.direction = "out"
            self.btnIncoming.setEnabled(True)
            self.btnEncrypt.setEnabled(True)
            self.btnDecrypt.setEnabled(True)

        # Send
        elif eventSource == self.btnDecrypt:
            self.btnDecrypt.setEnabled(True)
            clientData = json.dumps({"action": "decrypt",
                                     "data": {
                                            "direction": self.direction,
                                            "msg": self.messageField.getText()
                                        }
                                     })

            self.client.sendto(clientData, ("127.0.0.1",2912))
            try:
                serverData, addr = self.client.recvfrom(2048)
                serverData = json.loads(serverData)

                if serverData["status"] == 0:
                    print serverData
                    self.messageField.setText(json.dumps(serverData["data"]))
                    self.statusActField.setForeground(Color.GREEN)
                    self.statusActField.setText("OK")
                else:
                    self.statusActField.setForeground(Color.RED)
                    self.statusActField.setText("Error: {}".format(json.dumps(serverData["data"])))

            except socket.timeout:
                pass

        elif eventSource == self.btnEncrypt:
            self.btnEncrypt.setEnabled(True)
            clientData = json.dumps({"action": "encrypt",
                                     "data": {
                                         "direction": self.direction,
                                         "msg": self.messageField.getText()
                                     }
                                     })

            self.client.sendto(clientData, ("127.0.0.1", 2912))
            try:
                serverData, addr = self.client.recvfrom(2048)
                serverData = json.loads(serverData)
                if serverData["status"] == 0:
                    if isinstance(serverData["data"], list):
                        self.messageField.setText(json.dumps(serverData["data"]))
                    else:
                        self.messageField.setText(serverData["data"])

                    self.statusActField.setForeground(Color.GREEN)
                    self.statusActField.setText("OK")
                else:
                    self.statusActField.setForeground(Color.RED)
                    self.statusActField.setText("Error: {}".format(json.dumps(serverData["data"])))

            except socket.timeout:
                pass

        self.client.close()


    def saveConfig(self, e=None):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.settimeout(self.socket_time_out)

        config = {
            'ref': self.refField.getText(),
            'private': self.privateKeyField.getText(),
            'public': self.publicKeyField.getText(),
        }

        self.callbacks.saveExtensionSetting("config", pickle.dumps(config))

        try:
            clientData = json.dumps({"action":"init",
                                     "data":{
                                         "ref":json.loads(self.refField.getText()),
                                         "private":self.privateKeyField.getText(),
                                         "public":self.publicKeyField.getText()
                                     }
                                    })

            self.client.sendto(clientData, ("127.0.0.1", 2912))

            serverData, addr = self.client.recvfrom(2048)
            print (serverData)

            self.statusConnField.setText("CONNECTED")
            self.statusActField.setForeground(Color.GREEN)
            self.statusActField.setText("OK")

        except socket.timeout:
            self.statusActField.setForeground(Color.RED)
            self.statusActField.setText("Error: Can't connect to the local server make sure parser.py is running!")
            pass

        except Exception as e:
            self.statusActField.setForeground(Color.RED)
            self.statusActField.setText("Error: make Sure the ref is a correct json!")

        self.client.close()

    def clearConfig(self, e=None):
        self.refField.setText("")
        self.privateKeyField.setText("")
        self.publicKeyField.setText("")
        self.statusConnField.setText("NOT CONNECTED")
        self.statusActField.setText("OK")
        self.messageField.setText("")

    def restoreConfig(self, e=None):
        storedConfig = self.callbacks.loadExtensionSetting("config")
        if storedConfig != None:
            config = pickle.loads(storedConfig)
            self.refField.setText(config["ref"])
            self.privateKeyField.setText(config["private"])
            self.publicKeyField.setText(config["public"])

    def getTabCaption(self):
        return ("WhatsApp Decoder")

    def getUiComponent(self):
        return self.tab
