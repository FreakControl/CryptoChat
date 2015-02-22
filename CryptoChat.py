#!/usr/bin/python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:        CryptoChat
# Purpose:     Secure P2P chat client
# Notes:       Encrypted with XOR + AES + base64
#              custom chat protocol
#
# Author:      Freak @ PopulusControl (aka sudoer)
#
# Created:     21/02/2015
# Copyright:   (c) Freak 2015
# Licence:     GPLv3
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------
import sys
import socket
import base64
import random
import string
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from threading import Thread
class CryptoClient():
	def __init__(self):
		print "Welcome to CryptoChat, a secure P2P chat client coded by Freak"
		print "if you dont know what your doing read the README.md!!!"
		self.IP = raw_input("Please enter the IP address you wish to chat with: ")
		self.PORT = int(raw_input("Enter the port for communication: "))
		self.EncryptKeyXOR = raw_input("Enter desired key for XOR encryption: ")
		self.EncryptKeyAES = hashlib.md5(raw_input("Enter a secure passphrase for AES")).hexdigest()
		###Shit for AES padding
		BS = 16
		self.pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
		self.unpad = lambda s : s[:-ord(s[len(s)-1:])]
		###Start chat server and client
		Thread(target=self.RecvMSG, args=()).start()
		self.SendMSG()
	def EncryptAES(self,raw):
		raw = self.pad(raw)
		iv = Random.new().read( AES.block_size )
		cipher = AES.new( self.EncryptKeyAES, AES.MODE_CBC, iv )
		return base64.b64encode( iv + cipher.encrypt( raw ) )
	def DecryptAES(self,enc):
		enc = base64.b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.EncryptKeyAES, AES.MODE_CBC, iv )
		return self.unpad(cipher.decrypt( enc[16:] ))
	def XOR(self,securekey,data,mode):
		if mode == 1:
			securekey=securekey[::-1]
		temp=''
		for char in securekey:
			for x in data:
				temp += chr(ord(x)^ord(char))
			data=temp
			temp=''
		return data	
	def EncryptMSG(self,data):
		data = self.XOR(self.EncryptKeyXOR,data,0)
		data = self.EncryptAES(data)
		return data
	def DecryptMSG(self,data):
		data = self.DecryptAES(data)
		data = self.XOR(self.EncryptKeyXOR,data,1)
		return data
	def SendMSG(self):
		clientsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
		while 1:
			message = raw_input("")
			if message.startswith("/send"): #send file command
				self.SendFILE(message.split(" ")[1])
			if message=="/leave":
				message = self.EncryptMSG("LEAVE")
				clientsock.sendto(message, (self.IP, self.PORT))
				sys.exit(0)
			else:
				message = self.EncryptMSG("MSG"+message)
				clientsock.sendto(message, (self.IP, self.PORT))
	def SendFILE(self,file_):
		clientsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
		try:
			ext = file_.split(".")[1]
		except:
			print "No extension! Using txt instead..." #derp
			ext="txt"
		data="FILE"+str(len(ext))+ext
		f=open(file_,"rb")
		data+=f.read()
		f.close()
		data = self.EncryptMSG(data)
		clientsock.sendto(data, (self.IP, self.PORT))
		print "File Sent!"
	def RandStr(self,length):
		return ''.join(random.choice(string.letters) for _ in range(length))
	def RecvMSG(self):
		serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #UDP
		serversocket.bind((self.IP, self.PORT))
		while 1:
			(data, addr) = serversocket.recvfrom(1024*1024*1024) # buffer size is 1 gbit (for large files/images)
			data = self.DecryptMSG(data)
			if data.startswith("FILE"):
				data=list(data)
				extlength = int(data[4])
				ext=''
				for i in range(5,extlength):
					ext+=data[i]
					del data[i]
				print addr[0] + " has sent a " + ext + " file!"
				FileName = self.RandStr(8)
				print "Downloading as " + FileName + "." + ext + " ..." #fuck file names as they could tell something about the file
				del data[:4]
				data=''.join(data)
				f = open(FileName+"."+ext,"wb")
				f.write(data)
				f.close()
				print "Saved."
			elif data.startswith("MSG"): # all messages start with "msg" to prevent file spamming
				data=list(data)
				del data[:3]
				data=''.join(data)
				print addr[0]+">	|	"+data
			elif data.startswith("LEAVE"):
				print addr[0]+" has left."
				sys.exit(0)

if __name__=="__main__":
	CryptoClient()
