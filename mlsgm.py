from sys import argv
from sys import exit
from os import path
from collections import Counter
from statistics import stdev

base64_charset =    ['+', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                     'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
                     'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                     'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                     'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                     'w', 'x', 'y', 'z']
hex_charset =       ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
                     'c', 'd', 'e', 'f']
bin_charset =       ['0', '1']
dec_charset =       ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
drop_list1 =        [' ', ',']
drop_list2 =        ['\\', 'x', ' ', ',']


def checkCharset(filebytes):
    file_charset = sorted(set(filebytes))
    if '=' in file_charset:
        file_charset.remove('=')
    if file_charset == base64_charset:
        perfect_match = 'base64'
        return perfect_match
    for a in drop_list1:
        if a in file_charset:
            file_charset.remove(a)
    if file_charset == bin_charset:
        perfect_match = 'binary'
        return perfect_match
    if file_charset == dec_charset:
        perfect_match = 'decimal'
        return perfect_match
    file_charset = sorted(set(filebytes.lower()))
    for a in drop_list2:
        if a in file_charset:
            file_charset.remove(a)
    if file_charset == hex_charset:
        perfect_match = 'hex'
        return perfect_match
    else:
        perfect_match = 'None'
    return perfect_match


def b64_mlsgm(filebytes):
    detect_type = 'None'
    file_length = len(filebytes)  # how many bytes in the 'file'
    file_charset = sorted(set(filebytes))  # sorted list of characters
    file_charset_len = len(file_charset)  # how many unique characters
    file_charcount = Counter(filebytes)  # Counter, how many of each characters
    top_two = [file_charcount.most_common(2)[0][0], file_charcount.most_common(2)[1][0]]  # two most common characters
    b64_bytecount = 0
    b64_charcount = []
    for a in base64_charset:
        b64_charcount.append(file_charcount[a])  # list of base64 character counts
        b64_bytecount += file_charcount[a]  # total number of possible base64 characters
    b64_pct = b64_bytecount / float(file_length)  # calculate the pct% of possible base64 characters present
    b64_missing_chars = b64_charcount.count(0)  # count how many base64 characters are not present
    null_count = file_charcount['A']  # total number of times 'A' appears, indicator of null padding
    null_pct = null_count / float(b64_bytecount)
    b64_dev = stdev(b64_charcount)
    if b64_pct > 0.6 and b64_missing_chars < 4:
        if b64_missing_chars == 0 and null_pct > 0.1:
            detect_type = 'base64_binary_file_or_null_padding'
            return detect_type
        elif b64_dev < 100:
            detect_type = 'base64_compressed_or_encrypted'
            return detect_type
        elif b64_missing_chars > 0  and 'A' not in top_two:
            detect_type = 'base64_character_substitution'
            return detect_type
    return detect_type


if len(argv) != 2:
    print ('Usage: {0} [filename]'.format(argv[0]))
    exit(1)

filename = str(argv[1])
if not path.exists(filename):
    print('File not found: {0}'.format(filename))
    exit(1)

with open(filename, 'r') as f:
    raw = f.read()

raw = raw.rstrip()
match = checkCharset(raw)
if match != 'None':
    print("{0}: perfect match {1}".format(filename, match))
    exit(0)

detect_type = b64_mlsgm(raw)
if detect_type != 'None':
    print("{0}: MLSGM match type: {1}".format(filename, detect_type))
