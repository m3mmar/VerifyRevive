#!/usr/bin/env python3
import sys, os, binascii
import hmac, hashlib
sys.path += [ os.path.join(os.path.split(__file__)[0], 'libs') ]
import serial
from intelhex import IntelHex

# 256 bit key , this key serve as Kauth
key = b'\x6e\x26\x88\x6e\x4e\x07\x07\xe1\xb3\x0f\x24\x16\x0e\x99\xb9\x12\xe4\x61\xc4\x24\xb3\x0f\x24\x16\x0e\x99\xb9\x12\xe4\x61\xc4\x24'
Cv = 1
Ct = 1
def main(argv):
   if len(argv) != 2:
      print('challenger.py <hexfile> <serialport>')
      sys.exit(2)

   global Cv
   global Ct   
   # Check if hexfile exists
   hexfile = argv[0]
   if not os.path.isfile(hexfile):
      print("ERROR: File not found:", hexfile)
      sys.exit(2)
   ih = IntelHex(hexfile)

   ser = serial.Serial(argv[1], 57600)

   # increment counter 
   Cv = Cv + 1
   # Generate nonce
   nonce = os.urandom(32)
   print("Nonce: ")
   print(binascii.hexlify(nonce))

   hmac_gen = hmac.new(key, None, hashlib.sha256)
   hmac_gen.update(('%s' %(Cv)).encode('utf-8'))
   hmac_gen.update(nonce)
   H = hmac_gen.digest()

   # Send attest request
   ser.write(('%s' %(Cv)).encode('utf-8'))
   ser.write(nonce)
   ser.write(H)

   # Wait for answer 'o' --> OK
   answer = ser.read()
   while answer != b'o':
       answer = ser.read()
   print(answer)

   # wait for attestation report
   answer = ser.read()
   if answer == b'1':
      # The remaining of healthy attestation report!
      answer = ser.read(33)
   elif answer == b'2':
      # Bad attestation report; no authenticity!
      answer = ser.read(32)
   else:
      # bad attestation report + proof of secure erasure
      answer = ser.read(64)

   ### Verifier has to check authenticity of report and Ct (and POE if exists!)###   
   # Mote answer 
   print("Mote answer:");
   print(binascii.hexlify(answer))

if __name__ == "__main__":
     main(sys.argv[1:])
