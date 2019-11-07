import os
import glob
import re
import base64
import binascii
import zlib
import magic
import codecs

mimetype = magic.Magic(mime=True)
pastes_dir = '/home/ubuntu/pastes/'	 # trailing slash is IMPORTANT here
BASE64_REGEX = re.compile('TV(oAAA|pBUl|pQAA|qAAA|qQAA|roAA|pFUu)[A-Za-z0-9/+]{112,}[\=]{0,2}')
B64URLSAFE_REGEX = re.compile('TV(oAAA|pBUl|pQAA|qAAA|qQAA|roAA|pFUu)[A-Za-z0-9_-]{112,}[\=]{0,2}')
DECSP_REGEX = re.compile('77\ 90\ (144\ 0\ 3\ 0\ 4\ 0|232\ 0\ 0\ 0\ 0\ 91|144\ 0\ 3\ 0\ 0\ 0|80\ 0\ 2\ 0\ 0\ 0|0\ 0\ 0\ 0\ 0\ 0|65\ 82\ 85\ 72\ 137\ 229|128\ 0\ 1\ 0\ 0\ 0|144\ 0\ 3\ 0\ 4\ 0|232\ 0\ 0\ 0\ 0\ 91)[0-9\ ]{254,}')
DECCM_REGEX = re.compile('77,90,(144,0,3,0,4,0|232,0,0,0,0,91|144,0,3,0,0,0|80,0,2,0,0,0|0,0,0,0,0,0|65,82,85,72,137,229|128,0,1,0,0,0|144,0,3,0,4,0|232,0,0,0,0,91)[0-9,]{254,}[0-9]{1}')
HEX_REGEX = re.compile('4d5a(00000000|41525548|50000200|80000100|90000300|e8000000|4552e8000000)[a-f0-9]{254,}', re.IGNORECASE)
HEXBASE_REGEX = re.compile('5456(71514141|70514141|6f414141|7042556c|71414141|726f4141)[a-f0-9]{254,}', re.IGNORECASE)
BIN_REGEX = re.compile('0100110101011010(00000000000000000000000000000000|01000001010100100101010101001000|01010000000000000000001000000000|10000000000000000000000100000000|10010000000000000000001100000000|11101000000000000000000000000000)[0-1]{1000,}')
GZ64_REGEX = re.compile('H4sIA[A-Za-z0-9/+]{252,}[\=]{0,2}')
GZENC_REGEX = re.compile('[a-zA-Z0-9/+]{250,}[\=]{0,2}')
BASE312_REGEX = re.compile('396\ 398\ (379|424|425|426)\ (377|378|393|423)\ (377|381|397|419)[0-9\ ]{254,}')


def decdump(infile):
    text = ''
    for line in str(infile).splitlines():
        text += line.rstrip()
    if DECSP_REGEX.search(text):
        print("decimal matched")
        match = DECSP_REGEX.search(text)
        try:
            elements = match.group(0).split(' ')
            frame = bytearray()
            for byte in elements:
                decimal = int(byte, 10)
                frame.append(decimal)
            bin = str(frame).encode()
            return bin
        except:
            print("Error decoding decimal")
            bin = "ERR"
            return bin
    elif DECCM_REGEX.search(text):
        print("decimal-comma matched")
        match = DECCM_REGEX.search(text)
        try:
            elements = match.group(0).split(',')
            frame = bytearray()
            for byte in elements:
                decimal = int(byte, 10)
                frame.append(decimal)
            bin = str(frame).encode()
            return bin
        except:
            print("Error decoding decimal")
            bin = "ERR"
            return bin
    else:
        print("No decimal string found")
        bin = "ERR"
        return bin


def bindump(infile):
    text = ''
    for line in str(infile).splitlines():
        text += line.rstrip()
    text = text.replace(" ", "")
    if BIN_REGEX.search(text):
        print("binary matched")
        match = BIN_REGEX.search(text)
        try:
            n = int(str('0b' + match.group(0)), 2)
            bin = binascii.unhexlify('%x' % n)
            return bin
        except:
            print("Error decoding binary")
            bin = "ERR"
            return bin
    else:
        print("No binary string found")
        bin = "ERR"
        return bin


def basedump(infile):
    text = ''
    for line in str(infile).splitlines():
        text += line.rstrip()
    if BASE64_REGEX.search(text):
        print("base64 matched")
        match = BASE64_REGEX.search(text)
        try:
            bin = base64.b64decode(match.group(0))
            return bin
        except:
            print("Error decoding base64")
            bin = "ERR"
            return bin
    if B64URLSAFE_REGEX.search(text):
        print("urlsafe matched")
        match = B64URLSAFE_REGEX.search(text)
        try:
            bin = base64.urlsafe_b64decode(match.group(0))
            return bin
        except:
            print("Error decoding urlsafe")
            bin = "ERR"
            return bin
    else:
        print("No base64 string found")
        bin = "ERR"
        return bin


def hexdump(infile):
    text = ''
    for line in str(infile).splitlines():
        text += line.rstrip()
    text = text.replace("0x", "")
    text = text.replace(",", "")
    if HEX_REGEX.search(text):
        print("hex matched")
        match = HEX_REGEX.search(text)
        try:
            bin = codecs.decode(match.group(0), 'hex')
            return bin
        except:
            print("Error decoding hex")
            bin = "ERR"
            return bin
    elif HEXBASE_REGEX.search(text):
        print("hexbase matched")
        match = HEXBASE_REGEX.search(text)
        try:
            bin = codecs.decode(match.group(0), 'hex')
            return bin
        except:
            print("Error decoding hex")
            bin = "ERR"
            return bin
    else:
        print("No hex string found")
        bin = "ERR"
        return bin


def hexbasedump(infile):
    text = ''
    for line in str(infile).splitlines():
        text += line.rstrip()
    text = text.replace(" ", "")
    text = text.replace("#", "A")
    bin = hexdump(text)
    if not (bin == 'ERR'):
        bin = basedump(bin)
    return bin


def gz64dump(infile):
    text = ''
    for line in str(infile).splitlines():
        text += line.rstrip()
    if GZ64_REGEX.search(text):
        print("basegzip matched")
        match = GZ64_REGEX.search(text)
        frame = bytearray()
        try:
            for a in base64.b64decode(text):
                frame.append(a)
        except:
            print("Error decoding base64")
            bin = "ERR"
        try:
            bin = zlib.decompress(bytes(frame), 15+32)
        except zlib.error:
            print("Error decompressing")
            bin = "ERR"
            return bin
        filetype = mimetype.from_buffer(bin)
        if filetype  == 'application/x-dosexec':
            return bin
        else:
            print("Error, not PE file. File type detected: " + filetype)
            bin = "ERR"
            return bin
    else:
        bin = "ERR"
        return bin


def gzencdump(infile):
    text = ''
    for line in str(infile).splitlines():
        text += line.rstrip()
    if GZENC_REGEX.search(text):
        print("gzencode matched")
        match = GZENC_REGEX.search(text)
        frame = bytearray()
        try:
            for a in base64.b64decode(match.group(0)):
                frame.append(a)
        except:
            print("Error decoding base64")
            bin = "ERR"
        try:
            bin = zlib.decompress(bytes(frame), -15)
        except zlib.error:
            print("Error decompressing")
            bin = "ERR"
            return bin
        filetype = mimetype.from_buffer(bin)
        if filetype  == 'application/x-dosexec':
            return bin
        else:
            print("Error, not PE file. File type detected: " + filetype)
            bin = "ERR"
            return bin


def base312dump(infile):
    text = ''
    for line in str(infile).splitlines():
        text += line.rstrip()
    text = text.replace(",", " ")
    if BASE312_REGEX.search(text):
        print("basethreetwelve matched")
        match = BASE312_REGEX.search(text)
        base_string = str(match.group(0))
        decoded_string = ""
        try:
            for a in base_string.split(" "):
                b = int(a) - 312
                decoded_string += chr(b)
            bin = base64.b64decode(decoded_string)
            return bin
        except:
            print("Error decoding")
            bin = "ERR"
            return bin


def write_file(data, filename):
    if not os.path.exists(filename):
        file = open(filename, 'wb')
        file.write(data)
        file.close()
        return
    else:
        print("paste already exists")


decoding_tuples = [('base64', basedump), ('basegzip', gz64dump),
                   ('basethreetwelve', base312dump), ('bin', bindump),
                   ('dec', decdump), ('hex', hexdump),
                   ('hexbase', hexbasedump), ('gzencode', gzencdump)]

for decoder in decoding_tuples:
    extension = decoder[0]
    decoder_function = decoder[1]
    files_list = glob.glob(pastes_dir + '*.' + extension)

    for filename in files_list:
        print(filename)

        with open(filename, 'rb') as f:
            raw = f.read()a

        bin = decoder_function(raw)

        if not (bin == 'ERR'):
            base = os.path.basename(filename)
            binout = pastes_dir + os.path.splitext(base)[0] + '.exe'
            write_file(bin, binout)
            os.remove(filename)
