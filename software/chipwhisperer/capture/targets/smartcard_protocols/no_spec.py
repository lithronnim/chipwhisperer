#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2013-2016, NewAE Technology Inc
# All rights reserved.
#
# Find this and more at newae.com - this file is part of the chipwhisperer
# project, http://www.assembla.com/spaces/chipwhisperer
#
#    This file is part of chipwhisperer.
#
#    chipwhisperer is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    chipwhisperer is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with chipwhisperer.  If not, see <http://www.gnu.org/licenses/>.
#=================================================

import logging
from _base import ProtocolTemplate

try:
    from smartcard.util import toHexString
    from smartcard.util import toBytes
except ImportError:
    raise ImportError("Smartcard libraries are missing")

class ProtocolUnspecified(ProtocolTemplate):
    _name = "Unspecified protocol"
    
    def __init__(self):
		ProtocolTemplate.__init__(self)
		
		self.params.addChildren([
			{'name': "Init command(s)", 'key': "listInitCmd", 'type': "str", 'value': "", 'tip': "List of APDU (hex format) send before capture seprate by ';'" },
			{'name': "Load Key", 'key': "loadkey",'type': "bool", 'value': False, "readonly": True},
			{'name':'Go Command','key':'cmdgo', 'type':'str', 'value':'00 88 00 00 $TEXT$'},
		])

    def loadEncryptionKey(self, key):
        if not self.findParam("loadkey").getValue():
            return
        if len(key) != 16:
            raise ValueError("Encryption key != 16 bytes??")
        status = self.hw.sendAPDU(0x80, 0x12, 0x00, 0x00, key)
        self.key = key
        #print status

    def go(self):
        if len(self.input) != 16:
            raise ValueError("Plaintext != 16 bytes??")
        cmd = self.findParam("cmdgo").getValue()
        cmd = self.replace(" ", "")
        cla = int(cmd[0:2], 16)
        ins = int(cmd[2:4], 16)
        p1 = int(cmd[4:6],16)
        p2 = int(cmd[6:8], 16)
        status = self.hw.sendAPDU(cla, ins, p1, p2, self.input)
        #print status

    def readOutput(self):
        (resp, pay) = self.hw.sendAPDU(0x80, 0xC0, 0x00, 0x00, rxdatalen=16)
        #print resp
        return pay
        
    def init(self):
		cmds = self.findParam("listInitCmd").split(";")
		for cmd in cmds:
			cmd = toBytes(cmd)
			if len(cmd) == 4:
				data = []
				le = 0
			elif len(cmd) == 5:
				data = []
				le = cmd[4]
			else:
				data = cmd[5: 5 + cmd[4]]
				le = 0
				if 5 + cmd[4] < len(cmd):
					le = cmd[-1]
			status = self.hw.sendAPDU(cmd[0], cmd[1], cmd[2], cmd[3], data, le)
			if status != 0x9000:
				raise IOError("Init failed : Invalid status %s" % hex(status))
				
	

