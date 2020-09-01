#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import sys, os, struct, binascii
import hmac, hashlib
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
sys.path += [ os.path.join(os.path.split(__file__)[0], 'libs') ]
import serial

PAGE_SIZE = 256

# 256 bit key
# For simplicity, this key act as K_Oauth and K_attest (those are mentioned in the paper!)
key = b'\x6e\x26\x88\x6e\x4e\x07\x07\xe1\xb3\x0f\x24\x16\x0e\x99\xb9\x12\xe4\x61\xc4\x24\xb3\x0f\x24\x16\x0e\x99\xb9\x12\xe4\x61\xc4\x24'
fixed_nonce_ChaCha20 = b'\x16\x88\x26\x6e\x4e\x07\x07\xe1\xb3\x0f\x24\xe6'

VCN_O = 1

def main(argv):
   print("ok")
   if len(argv) != 2:
      print('serial_loader.py <binfile> <serialport>')
      sys.exit(2)

   global VCN_O   
   # Check if binfile exists
   binfile = argv[0]
   if not os.path.isfile(binfile):
      print("ERROR: File not found:", binfile)
      sys.exit(2)
   ser = serial.Serial(argv[1], 57600)
   f = open(binfile, "rb")
   filecontent = f.read()
   # Decode some stuff from metadata header..
   total = struct.unpack("<H", filecontent[:2])[0]
   #data = struct.unpack("<H", filecontent[2:4])[0]
   twoword = struct.unpack("<H", filecontent[4:6])[0]

   # Calculate metadata header size
   header_size = 6 + (2 * twoword) + 32

   # Write encrypted metadata
   cipher = ChaCha20.new(key=key, nonce=fixed_nonce_ChaCha20)
   ser.write(cipher.encrypt(filecontent[:header_size]))

   # Wait for answer 'o' --> OK
   answer = ser.read()
   while answer != b'o':
       answer = ser.read()
   print(answer)

   # Write encrypted image
   for i in range(0,total//PAGE_SIZE):
      cipher = ChaCha20.new(key=key, nonce=fixed_nonce_ChaCha20)
      ser.write(cipher.encrypt(filecontent[header_size+(PAGE_SIZE*i):header_size+PAGE_SIZE*(i+1)]))
      # Wait for answer 'o' --> OK
      answer = ser.read()
      while answer != b'o':
          answer = ser.read()
      print(answer)

   if total%PAGE_SIZE:
       cipher = ChaCha20.new(key=key, nonce=fixed_nonce_ChaCha20)
       ser.write(cipher.encrypt(filecontent[-(total%PAGE_SIZE):]))
       # Wait for answer 'o' --> OK
       answer = ser.read()
       while answer != b'o':
           answer = ser.read()
       print(answer)

   #Send VCN_O + HMAC to authenticate Operator    
   VCN_O = (VCN_O + 1)%255
   hmac_gen = hmac.new(key, None, hashlib.sha256)
   hmac_gen.update(('%s' %(VCN_O)).encode('utf-8'))
   ser.write(('%s' %(VCN_O)).encode('utf-8'))
   ser.write(hmac_gen.digest())

   # Wait for answer 'd' --> Done
   answer = ser.read()
   while answer != b'd':
       answer = ser.read()
   print(answer)

   # Get POU (proof of secure update) from mote
   pou = ser.read(32)
   print(pou)
   print("POU is received! Everything is Alright!!")

if __name__ == "__main__":
     main(sys.argv[1:])
