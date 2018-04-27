import sys
import os
import glob
import re
import base64
import binascii

pastes_dir = '/home/ubuntu/pastes/'	# trailing slash is IMPORTANT here
BASE64_REGEX = re.compile('TV(oAAA|pBUl|pQAA|qAAA|qQAA|roAA)[A-Za-z0-9/+]{112,}[\=]{0,2}')
B64URLSAFE_REGEX = re.compile('TV(oAAA|pBUl|pQAA|qAAA|qQAA|roAA)[A-Za-z0-9_-]{112,}[\=]{0,2}')
DECSP_REGEX = re.compile('77\ 90\ (144\ 0\ 3\ 0\ 4\ 0|232\ 0\ 0\ 0\ 0\ 91|144\ 0\ 3\ 0\ 0\ 0|80\ 0\ 2\ 0\ 0\ 0|0\ 0\ 0\ 0\ 0\ 0|65\ 82\ 85\ 72\ 137\ 229|128\ 0\ 1\ 0\ 0\ 0|144\ 0\ 3\ 0\ 4\ 0|232\ 0\ 0\ 0\ 0\ 91)[0-9\ ]{254,}')
DECCM_REGEX = re.compile('77,90,(144,0,3,0,4,0|232,0,0,0,0,91|144,0,3,0,0,0|80,0,2,0,0,0|0,0,0,0,0,0|65,82,85,72,137,229|128,0,1,0,0,0|144,0,3,0,4,0|232,0,0,0,0,91)[0-9,]{254,}[0-9]{1}')
HEX_REGEX = re.compile('4d5a(00000000|41525548|50000200|80000100|90000300|e8000000)[a-f0-9]{254,}', re.IGNORECASE)
HEXBASE_REGEX = re.compile('5456(71514141|70514141|6f414141|7042556c|71414141|726f4141)[a-f0-9]{254,}', re.IGNORECASE)
BIN_REGEX = re.compile('0100110101011010(00000000000000000000000000000000|01000001010100100101010101001000|01010000000000000000001000000000|10000000000000000000000100000000|10010000000000000000001100000000|11101000000000000000000000000000)[0-1]{1000,}')

def decdump(text):
  if DECSP_REGEX.search(text):
    print("decimal matched")
    match = DECSP_REGEX.search(text)
    try:
      elements = match.group(0).split(' ')
      frame = bytearray()
      for byte in elements:
        decimal = int(byte, 10)
        frame.append(decimal)
      bin = str(frame)
      return bin
    except:
      print "Error decoding decimal"
      bin = "ERR"
      return bin
  elif DECCM_REGEX.search(text):
    print "decimal-comma matched"
    match = DECCM_REGEX.search(text)
    try:
      elements = match.group(0).split(',')
      frame = bytearray()
      for byte in elements:
        decimal = int(byte, 10)
        frame.append(decimal)
      bin = str(frame)
      return bin
    except:
      print "Error decoding decimal"
      bin = "ERR"
      return bin
  else:
    print "No decimal string found"
    bin = "ERR"
    return bin

def bindump(text):
  if BIN_REGEX.search(text):
    print "binary matched"
    match = BIN_REGEX.search(text)
    try:
      n = int(str('0b' + match.group(0)), 2)
      bin = binascii.unhexlify('%x' % n)
      return bin
    except:
      print "Error decoding binary"
      bin = "ERR"
      return bin
  else:
    print "No binary string found"
    bin = "ERR"
    return bin

def basedump(text):
  if BASE64_REGEX.search(text):
    print "base64 matched"
    match = BASE64_REGEX.search(text)
    try:
      bin = base64.b64decode(match.group(0))
      return bin
    except:
      print "Error decoding base64"
      bin = "ERR"
      return bin
  if B64URLSAFE_REGEX.search(text):
    print "urlsafe matched"
    match = B64URLSAFE_REGEX.search(text)
    try:
      bin = base64.urlsafe_b64decode(match.group(0))
      return bin
    except:
      print "Error decoding urlsafe"
      bin = "ERR"
      return bin
  else:
    print "No base64 string found"
    bin = "ERR"
    return bin

def write_file(data, filename):
  if not os.path.exists(filename):
    file = open(filename, 'w')
    file.write(data)
    file.close()
    return
  else:
    print 'paste already exists'

def hexdump(text):
  if HEX_REGEX.search(text):
    print "hex matched"
    match = HEX_REGEX.search(text)
    try:
      bin = match.group(0).decode('hex')
      return bin
    except:
      print "Error decoding hex"
      bin = "ERR"
      return bin
  elif HEXBASE_REGEX.search(text):
    print "hexbase matched"
    match = HEXBASE_REGEX.search(text)
    try:
      bin = match.group(0).decode('hex')
      return bin
    except:
      print "Error decoding hex"
      bin = "ERR"
      return bin
  else:
    print "No hex string found"
    bin = "ERR"
    return bin

ls = pastes_dir + '*.bin'
binlist = glob.glob(ls)
for filename in binlist:
  print filename
  raw=open(filename).readlines()
  for n,line in enumerate(raw):
    raw[n]=line.rstrip()
    raw[n]=raw[n].replace(" ", "")
  raw = ''.join(raw)
  bin = bindump(raw)
  if not (bin == 'ERR'):
    base = os.path.basename(filename)
    binout = pastes_dir + os.path.splitext(base)[0] + '.exe'
    write_file(bin, binout)
    os.remove(filename)

ls = pastes_dir + '*.b64'
baselist = glob.glob(ls)
for filename in baselist:
  print filename
  raw=open(filename).readlines()
  for n,line in enumerate(raw):
    raw[n]=line.rstrip()
  raw = ''.join(raw)
  bin = basedump(raw)
  if not (bin == 'ERR'):
    base = os.path.basename(filename)
    binout = pastes_dir + os.path.splitext(base)[0] + '.exe'
    write_file(bin, binout)
    os.remove(filename)

ls = pastes_dir + '*.hex'
hexlist = glob.glob(ls)
for filename in hexlist:
  print filename
  raw=open(filename).readlines()
  for n,line in enumerate(raw):
    raw[n]=line.rstrip()
    raw[n]=raw[n].replace(" ", "")
  raw = ''.join(raw)
  bin = hexdump(raw)
  if not (bin == 'ERR'):
    base = os.path.basename(filename)
    binout = pastes_dir + os.path.splitext(base)[0] + '.exe'
    write_file(bin, binout)
    os.remove(filename)

ls = pastes_dir + '*.hexbase'
hexblist = glob.glob(ls)
for filename in hexblist:
  print filename
  raw=open(filename).readlines()
  for n,line in enumerate(raw):
    raw[n]=line.rstrip()
    raw[n]=raw[n].replace(" ", "")
    raw[n]=raw[n].replace("#", "A")
  raw = ''.join(raw)
  bin = hexdump(raw)
  if not (bin == 'ERR'):
    bin = basedump(bin)
  if not (bin == 'ERR'):
    base = os.path.basename(filename)
    binout = pastes_dir + os.path.splitext(base)[0] + '.exe'
    write_file(bin, binout)
    os.remove(filename)

ls = pastes_dir + '*.dec'
declist = glob.glob(ls)
for filename in declist:
  print filename
  raw=open(filename).readlines()
  for n,line in enumerate(raw):
    raw[n]=line.rstrip()
  raw = ''.join(raw)
  bin = decdump(raw)
  if not (bin == 'ERR'):
    base = os.path.basename(filename)
    binout = pastes_dir + os.path.splitext(base)[0] + '.exe'
    write_file(bin, binout)
    os.remove(filename)
