import requests
import os
import time
import re
import json

start = time.time()
url_pastebin_scraping = 'https://scrape.pastebin.com/api_scraping.php'
limit = 250
min_size = 1000
pastes_dir = '/home/ubuntu/pastes/'  # Trailing slash is important here!
originals_dir = '/home/ubuntu/pastes/origraw/'  # Trailing slash is important here!
logfile = pastes_dir + 'pastes.json'

# compile regular expressions for hex_find function
HEX_0 = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}90[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}03[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}04[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00')
HEX_1 = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}e8[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5b')
HEX_2 = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}90[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}03[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00')
HEX_3 = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}50[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}02[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00')
HEX_4 = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00')
HEX_5 = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}41[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}52[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}55[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}48[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}89[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}e5')
HEX_6 = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}80[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}01[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00')
HEX_7 = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}90[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}03[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}04[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00')
HEX_8 = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}e8[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}00[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,4}5b')

# list of suspicious accounts to track no matter what they post
# this should spin out into its own project
userlist = ['pmelson']


def posh_find(text):
    # make term searches case insensitive
    txtlower = text.lower()
    if '/c"powershell' in txtlower:
        return True
    if '/c powershell' in txtlower:
        return True
    if 'powershell -' in txtlower:
        return True
    if 'powershell /' in txtlower:
        return True
    if 'powershell.exe -' in txtlower:
        return True
    if '\1.0\powershell.exe' in txtlower:
        return True
    if '\\1.0\\powershell.exe' in txtlower:
        return True
    if '-runas32' in txtlower:
        return True
    if '::createthread' in txtlower:
        return True
    if ' -bxor' in txtlower:
        return True
    if '[system.convert]::' in txtlower:
        return True
    if 'frombase64string(' in txtlower:
        return True
    if 'new-object system.io.' in txtlower:
        return True
    if '[system.net.' in txtlower:
        return True
    if 'system.reflection.assemblyname' in txtlower:
        return True
    if 'x509enrollment.cbinaryconverter' in txtlower:
        return True
    if 'convertto-securestring' in txtlower:
        return True
    # 'powershell'
    if '93ZXJzaGVsb' in text:
        return True
    if 'd2Vyc2hlbGw' in text:
        return True
    if 'dlcnNoZWxs' in text:
        return True
    if '8Ad2UAcnMAaGUAbG' in text:
        return True
    if 'b3cAZXIAc2gAZWw' in text:
        return True
    if '8Ad2UAcnMAaGUAbG' in text:
        return True
    # 'PowerShell'
    if '93ZXJTaGVsb' in text:
        return True
    if 'd2VyU2hlbG' in text:
        return True
    if '3dlclNoZWx' in text:
        return True
    if '8Ad2UAclMAaGUAbG' in text:
        return True
    if '3cAZXIAU2gAZWw' in text:
        return True
    # '[System.Convert]::'
    if 'N5c3RlbS5Db252ZXJ0XT' in text:
        return True
    if 'eXN0ZW0uQ29udmVydF06O' in text:
        return True
    if 'lzdGVtLkNvbnZlcnRdO' in text:
        return True
    if 'MAeXMAdGUAbS4AQ28AbnYAZXIAdF0AO' in text:
        return True
    if 'AHlzAHRlAG0uAENvAG52AGVyAHRdAD' in text:
        return True
    if 'B5cwB0ZQBtLgBDbwBudgBlcgB0XQ' in text:
        return True
    # 'FromBase64'
    if 'JvbUJhc2U2N' in text:
        return True
    if 'b21CYXNlNj' in text:
        return True
    if 'cm9tQmFzZTY' in text:
        return True
    if 'IAb20AQmEAc2UAN' in text:
        return True
    if 'AG9tAEJhAHNlADY0' in text:
        return True
    if 'gBvbQBCYQBzZQA2' in text:
        return True
    # 'New-Object System.IO.'
    if 'V3LU9iamVjdCBTeXN0ZW0uSU' in text:
        return True
    if 'ldy1PYmplY3QgU3lzdGVtLklP' in text:
        return True
    if 'ZXctT2JqZWN0IFN5c3RlbS5JT' in text:
        return True
    if 'UAdy0AT2IAamUAY3QAIFMAeXMAdGUAbS4ASU8' in text:
        return True
    if 'lAHctAE9iAGplAGN0ACBTAHlzAHRlAG0uAElPA' in text:
        return True
    if 'ZQB3LQBPYgBqZQBjdAAgUwB5cwB0ZQBtLgBJ' in text:
        return True
    # '[System.Net.'
    if 'N5c3RlbS5OZX' in text:
        return True
    if 'TeXN0ZW0uTmV0' in text:
        return True
    if 'U3lzdGVtLk5ld' in text:
        return True
    if 'MAeXMAdGUAbS4ATmUAd' in text:
        return True
    if 'TAHlzAHRlAG0uAE5lAH' in text:
        return True
    if 'UwB5cwB0ZQBtLgBOZQB0' in text:
        return True
    # 'System.Reflection.AssemblyName'
    if 'lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHlO' in text:
        return True
    if '5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5TmFt' in text:
        return True
    if 'XN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseU5hb' in text:
        return True
    if 'kAc3QAZW0ALlIAZWYAbGUAY3QAaW8Abi4AQXMAc2UAbWIAbHkATmE' in text:
        return True
    if '5AHN0AGVtAC5SAGVmAGxlAGN0AGlvAG4uAEFzAHNlAG1iAGx5AE5hAG' in text:
        return True
    if 'QBzdABlbQAuUgBlZgBsZQBjdABpbwBuLgBBcwBzZQBtYgBseQBOYQBt' in text:
        return True
    # '::CreateThread'
    if 'pDcmVhdGVUaHJlY' in text:
        return True
    if '6Q3JlYXRlVGhyZW' in text:
        return True
    if 'kNyZWF0ZVRocmVh' in text:
        return True
    if 'oAQ3IAZWEAdGUAVGgAcmUAY' in text:
        return True
    if 'AENyAGVhAHRlAFRoAHJlAG' in text:
        return True
    if 'gBDcgBlYQB0ZQBUaAByZQB' in text:
        return True
    # 'X509Enrollment.CBinaryConverter'
    if 'UwOUVucm9sbG1lbnQuQ0JpbmFyeUNvbnZlcnR' in text:
        return True
    if '1MDlFbnJvbGxtZW50LkNCaW5hcnlDb252ZXJ0Z' in text:
        return True
    if 'NTA5RW5yb2xsbWVudC5DQmluYXJ5Q29udmVydG' in text:
        return True
    if 'UAMDkARW4Acm8AbGwAbWUAbnQALkMAQmkAbmEAcnkAQ28AbnYAZXIAdG' in text:
        return True
    if '1ADA5AEVuAHJvAGxsAG1lAG50AC5DAEJpAG5hAHJ5AENvAG52AGVyAHR' in text:
        return True
    if 'NQAwOQBFbgBybwBsbABtZQBudAAuQwBCaQBuYQByeQBDbwBudgBlcgB0' in text:
        return True
    # 'ConvertTo-SecureString'
    if '9udmVydFRvLVNlY3VyZVN0cmlu' in text:
        return True
    if 'vbnZlcnRUby1TZWN1cmVTdHJpb' in text:
        return True
    if 'b252ZXJ0VG8tU2VjdXJlU3RyaW' in text:
        return True
    if '8AbnYAZXIAdFQAby0AU2UAY3UAcmUAU3QAcmkAb' in text:
        return True
    if 'vAG52AGVyAHRUAG8tAFNlAGN1AHJlAFN0AHJpAG' in text:
        return True
    if 'bwBudgBlcgB0VABvLQBTZQBjdQByZQBTdAByaQB' in text:
        return True
    # ' -bxor'
    if 'IC1ieG9y' in text:
        return True
    if 'AtYnhvcg' in text:
        return True
    if 'LWJ4b3I' in text:
        return True
    if 'IC0AYngAb3' in text:
        return True
    if 'tAGJ4AG9y' in text:
        return True
    if 'LQBieABvc' in text:
        return True
    if "<PCSettings>" in text:
        return True
    if "<DeepLink>" in text:
        return True
    if "So MAny scrapers hahahaha" in text:
        return True



def dec_find(text):
    if '77 90 144 0 3 0 4 0' in text:
        return True
    if '77 90 232 0 0 0 0 91' in text:
        return True
    if '77 90 144 0 3 0 0 0' in text:
        return True
    if '77 90 80 0 2 0 0 0' in text:
        return True
    if '77 90 0 0 0 0 0 0' in text:
        return True
    if '77 90 65 82 85 72 137 229' in text:
        return True
    if '77 90 128 0 1 0 0 0' in text:
        return True
    if '77,90,144,0,3,0,4,0,' in text:
        return True
    if '77,90,232,0,0,0,0,91,' in text:
        return True
    if '77,90,144,0,3,0,0,0,' in text:
        return True
    if '77,90,80,0,2,0,0,0,' in text:
        return True
    if '77,90,0,0,0,0,0,0,' in text:
        return True
    if '77,90,65,82,85,72,137,229,' in text:
        return True
    if '77,90,128,0,1,0,0,0,' in text:
        return True
    if '77, 90, 144, 0, 3, 0, 4, 0,' in text:
        return True
    if '77, 90, 232, 0, 0, 0, 0, 91,' in text:
        return True
    if '77, 90, 144, 0, 3, 0, 0, 0,' in text:
        return True
    if '77, 90, 80, 0, 2, 0, 0, 0,' in text:
        return True
    if '77, 90, 0, 0, 0, 0, 0, 0,' in text:
        return True
    if '77, 90, 65, 82, 85, 72, 137, 229,' in text:
        return True
    if '77, 90, 128, 0, 1, 0, 0, 0,' in text:
        return True


def bin_find(text):
    if '010011010101101000000000000000000000000000000000' in text:
        return True
    if '010011010101101001000001010100100101010101001000' in text:
        return True
    if '010011010101101001010000000000000000001000000000' in text:
        return True
    if '010011010101101010000000000000000000000100000000' in text:
        return True
    if '010011010101101010010000000000000000001100000000' in text:
        return True
    if '010011010101101011101000000000000000000000000000' in text:
        return True
    if '0100 1101 0101 1010 0000 0000 0000 0000 0000 0000 0000 0000' in text:
        return True
    if '0100 1101 0101 1010 0100 0001 0101 0010 0101 0101 0100 1000' in text:
        return True
    if '0100 1101 0101 1010 0101 0000 0000 0000 0000 0010 0000 0000' in text:
        return True
    if '0100 1101 0101 1010 1000 0000 0000 0000 0000 0001 0000 0000' in text:
        return True
    if '0100 1101 0101 1010 1001 0000 0000 0000 0000 0011 0000 0000' in text:
        return True
    if '0100 1101 0101 1010 1110 1000 0000 0000 0000 0000 0000 0000' in text:
        return True
    if '01 00 11 01 01 01 10 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 01 00 00 01 01 01 00 10 01 01 01 01 01 00 10 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 01 01 00 00 00 00 00 00 00 00 00 10 00 00 00 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 10 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 10 01 00 00 00 00 00 00 00 00 00 11 00 00 00 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 11 10 10 00 00 00 00 00 00 00 00 00 00 00 00 00' in text:
        return True


def bin_find(text):
    if '010011010101101000000000000000000000000000000000' in text:
        return True
    if '010011010101101001000001010100100101010101001000' in text:
        return True
    if '010011010101101001010000000000000000001000000000' in text:
        return True
    if '010011010101101010000000000000000000000100000000' in text:
        return True
    if '010011010101101010010000000000000000001100000000' in text:
        return True
    if '010011010101101011101000000000000000000000000000' in text:
        return True
    if '0100 1101 0101 1010 0000 0000 0000 0000 0000 0000 0000 0000' in text:
        return True
    if '0100 1101 0101 1010 0100 0001 0101 0010 0101 0101 0100 1000' in text:
        return True
    if '0100 1101 0101 1010 0101 0000 0000 0000 0000 0010 0000 0000' in text:
        return True
    if '0100 1101 0101 1010 1000 0000 0000 0000 0000 0001 0000 0000' in text:
        return True
    if '0100 1101 0101 1010 1001 0000 0000 0000 0000 0011 0000 0000' in text:
        return True
    if '0100 1101 0101 1010 1110 1000 0000 0000 0000 0000 0000 0000' in text:
        return True
    if '01 00 11 01 01 01 10 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 01 00 00 01 01 01 00 10 01 01 01 01 01 00 10 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 01 01 00 00 00 00 00 00 00 00 00 10 00 00 00 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 10 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 10 01 00 00 00 00 00 00 00 00 00 11 00 00 00 00' in text:
        return True
    if '01 00 11 01 01 01 10 10 11 10 10 00 00 00 00 00 00 00 00 00 00 00 00 00' in text:
        return True


def base64_find(text):
    if 'TVqQAAMAAAAEAAAA' in text:
        return True
    if 'TVpQAAIAAAAEAA8A' in text:
        return True
    if 'TVoAAAAAAAAAAAAA' in text:
        return True
    if 'TVpBUlVIieVIgewg' in text:
        return True
    if 'TVqAAAEAAAAEABAA' in text:
        return True
    if 'TVroAAAAAFtSRVWJ' in text:
        return True
    if 'TVqQAAMABAAAAAAA' in text:
        return True
    if 'TVpBUlVIieVIgewgAAAA' in text:
        return True
    if 'kJCQkE1aQVJVSInlSIHsIAAAA' in text:
        return True
    if 'pcyBwcm9ncm' in text:
        return True


def doublebase_find(text):
    if 'VFZxUUFBTUFBQUFFQUFBQ' in text:
        return True
    if 'VFZwUUFBSUFBQUFFQUE4Q' in text:
        return True
    if 'VFZvQUFBQUFBQUFBQUFBQ' in text:
        return True
    if 'VFZwQlVsVklpZVZJZ2V3Z' in text:
        return True
    if 'VFZxQUFBRUFBQUFFQUJBQ' in text:
        return True
    if 'VFZyb0FBQUFBRnRTUlZXS' in text:
        return True
    if 'VFZxUUFBTUFCQUFBQUFBQ' in text:
        return True


def doublewidebase_find(text):
    if 'VABWAHEAUQBBAEEATQBBAEEAQQBBAEUAQQBBAEEAQQ' in text:
        return True
    if 'VABWAHAAUQBBAEEASQBBAEEAQQBBAEUAQQBBADgAQQ' in text:
        return True
    if 'VABWAG8AQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQ' in text:
        return True
    if 'VABWAHAAQgBVAGwAVgBJAGkAZQBWAEkAZwBlAHcAZw' in text:
        return True
    if 'VABWAHEAQQBBAEEARQBBAEEAQQBBAEUAQQBCAEEAQQ' in text:
        return True
    if 'VABWAHIAbwBBAEEAQQBBAEEARgB0AFMAUgBWAFcASg' in text:
        return True
    if 'VABWAHEAUQBBAEEATQBBAEIAQQBBAEEAQQBBAEEAQQ' in text:
        return True
    if 'VABWAHAAQgBVAGwAVgBJAGkAZQBWAEkAZwBlAHcAZwBBAEEAQQ' in text:
        return True
    if 'awBKAEMAUQBrAEUAMQBhAFEAVgBKAFYAUwBJAG4AbABTAEkASABzAEkAQQBBAEEAQQ' in text:
        return True


def exe_find(text):
    if '\x4d\x5a\x90\x00\x03\x00\x00\x00' in text:
        return True
    if '\x4d\x5a\x50\x00\x02\x00\x00\x00' in text:
        return True
    if '\x4d\x5a\x00\x00\x00\x00\x00\x00' in text:
        return True
    if '\x4d\x5a\x41\x52\x55\x48\x89\xe5' in text:
        return True
    if '\x4d\x5a\x80\x00\x01\x00\x00\x00' in text:
        return True
    if '\x4d\x5a\x90\x00\x03\x00\x04\x00' in text:
        return True
    if '\x4d\x5a\xe8\x00\x00\x00\x00\x5b' in text:
        return True


def hex_find(text):
    txtlower = text.lower()
    if '4d5a900003000000' in txtlower:
        return True
    if '4d5a500002000000' in txtlower:
        return True
    if '4d5a000000000000' in txtlower:
        return True
    if '4d5a4152554889e5' in txtlower:
        return True
    if '4d5a800001000000' in txtlower:
        return True
    if '4d5a900003000400' in txtlower:
        return True
    if '4d5ae8000000005b' in txtlower:
        return True
    if HEX_0.search(txtlower):
        return True
    if HEX_1.search(txtlower):
        return True
    if HEX_2.search(txtlower):
        return True
    if HEX_3.search(txtlower):
        return True
    if HEX_4.search(txtlower):
        return True
    if HEX_5.search(txtlower):
        return True
    if HEX_6.search(txtlower):
        return True
    if HEX_7.search(txtlower):
        return True
    if HEX_8.search(txtlower):
        return True


def hexbase_find(text):
    if '5456715141414d414141414541414141' in text:
        return True
    if '5456715141414D414141414541414141' in text:
        return True
    if '54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41' in text:
        return True
    if '54 56 71 51 41 41 4D 41 41 41 41 45 41 41 41 41' in text:
        return True
    if '54567051414149414141414541413841' in text:
        return True
    if '54 56 70 51 41 41 49 41 41 41 41 45 41 41 38 41' in text:
        return True
    if '54566f41414141414141414141414141' in text:
        return True
    if '54566F41414141414141414141414141' in text:
        return True
    if '54 56 6f 41 41 41 41 41 41 41 41 41 41 41 41 41' in text:
        return True
    if '54 56 6F 41 41 41 41 41 41 41 41 41 41 41 41 41' in text:
        return True
    if '54567042556c56496965564967657767' in text:
        return True
    if '54567042556C56496965564967657767' in text:
        return True
    if '54 56 70 42 55 6c 56 49 69 65 56 49 67 65 77 67' in text:
        return True
    if '54 56 70 42 55 6C 56 49 69 65 56 49 67 65 77 67' in text:
        return True
    if '54567141414145414141414541424141' in text:
        return True
    if '54 56 71 41 41 41 45 41 41 41 41 45 41 42 41 41' in text:
        return True
    if '5456726f41414141414674535256574a' in text:
        return True
    if '5456726F41414141414674535256574A' in text:
        return True
    if '54 56 72 6f 41 41 41 41 41 46 74 53 52 56 57 4a' in text:
        return True
    if '54 56 72 6F 41 41 41 41 41 46 74 53 52 56 57 4A' in text:
        return True
    if '5456715141414d414241414141414141' in text:
        return True
    if '5456715141414D414241414141414141' in text:
        return True
    if '54 56 71 51 41 41 4d 41 42 41 41 41 41 41 41 41' in text:
        return True
    if '54 56 71 51 41 41 4D 41 42 41 41 41 41 41 41 41' in text:
        return True


def basehex_find(text):
    if 'NGQ1YTkwMDAwMzAwMDAwMA' in text:
        return True
    if 'NEQ1QTkwMDAwMzAwMDAwMA' in text:
        return True
    if 'NGQ1YTUwMDAwMjAwMDAwMA' in text:
        return True
    if 'NEQ1QTUwMDAwMjAwMDAwMA' in text:
        return True
    if 'NGQ1YTAwMDAwMDAwMDAwMA' in text:
        return True
    if 'NEQ1QTAwMDAwMDAwMDAwMA' in text:
        return True
    if 'NGQ1YTQxNTI1NTQ4ODllNQ' in text:
        return True
    if 'NEQ1QTQxNTI1NTQ4ODlFNQ' in text:
        return True
    if 'NGQ1YTgwMDAwMTAwMDAwMA' in text:
        return True
    if 'NEQ1QTgwMDAwMTAwMDAwMA' in text:
        return True
    if 'NGQ1YTkwMDAwMzAwMDQwMA' in text:
        return True
    if 'NEQ1QTkwMDAwMzAwMDQwMA' in text:
        return True
    if 'NGQ1YWU4MDAwMDAwMDA1Yg' in text:
        return True
    if 'NEQ1QUU4MDAwMDAwMDA1Qg' in text:
        return True
    if 'NGQgNWEgOTAgMDAgMDMgMDAgMDQgMDA' in text:
        return True
    if 'NEQgNUEgOTAgMDAgMDMgMDAgMDQgMDA' in text:
        return True
    if 'NGQgNWEgZTggMDAgMDAgMDAgMDAgNWI' in text:
        return True
    if 'NEQgNUEgRTggMDAgMDAgMDAgMDAgNUI' in text:
        return True
    if 'NGQgNWEgOTAgMDAgMDMgMDAgMDAgMDA' in text:
        return True
    if 'NEQgNUEgOTAgMDAgMDMgMDAgMDAgMDA' in text:
        return True
    if 'NGQgNWEgNTAgMDAgMDIgMDAgMDAgMDA' in text:
        return True
    if 'NEQgNUEgNTAgMDAgMDIgMDAgMDAgMDA' in text:
        return True
    if 'NGQgNWEgMDAgMDAgMDAgMDAgMDAgMDA' in text:
        return True
    if 'NEQgNUEgMDAgMDAgMDAgMDAgMDAgMDA' in text:
        return True
    if 'NGQgNWEgNDEgNTIgNTUgNDggODkgZTU' in text:
        return True
    if 'NEQgNUEgNDEgNTIgNTUgNDggODkgRTU' in text:
        return True
    if 'NGQgNWEgODAgMDAgMDEgMDAgMDAgMDA' in text:
        return True
    if 'NEQgNUEgODAgMDAgMDEgMDAgMDAgMDA' in text:
        return True
    if 'NGQgNWEgOTAgMDAgMDMgMDAgMDQgMDA' in text:
        return True
    if 'NEQgNUEgOTAgMDAgMDMgMDAgMDQgMDA' in text:
        return True
    if 'NGQgNWEgZTggMDAgMDAgMDAgMDAgNWI' in text:
        return True
    if 'NEQgNUEgRTggMDAgMDAgMDAgMDAgNUI' in text:
        return True
    if 'MHg0ZCwweDVhLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg' in text:
        return True
    if 'MHg0RCwweDVBLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg' in text:
        return True
    if 'MHg0ZCwweDVhLDB4ZTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDViCg' in text:
        return True
    if 'MHg0RCwweDVBLDB4RTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDVCCg' in text:
        return True
    if 'MHg0ZCwweDVhLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwMCwweDAwCg' in text:
        return True
    if 'MHg0RCwweDVBLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwMCwweDAwCg' in text:
        return True
    if 'MHg0ZCwweDVhLDB4NTAsMHgwMCwweDAyLDB4MDAsMHgwMCwweDAwCg' in text:
        return True
    if 'MHg0RCwweDVBLDB4NTAsMHgwMCwweDAyLDB4MDAsMHgwMCwweDAwCg' in text:
        return True
    if 'MHg0ZCwweDVhLDB4MDAsMHgwMCwweDAwLDB4MDAsMHgwMCwweDAwCg' in text:
        return True
    if 'MHg0RCwweDVBLDB4MDAsMHgwMCwweDAwLDB4MDAsMHgwMCwweDAwCg' in text:
        return True
    if 'MHg0ZCwweDVhLDB4NDEsMHg1MiwweDU1LDB4NDgsMHg4OSwweGU1Cg' in text:
        return True
    if 'MHg0RCwweDVBLDB4NDEsMHg1MiwweDU1LDB4NDgsMHg4OSwweEU1Cg' in text:
        return True
    if 'MHg0ZCwweDVhLDB4ODAsMHgwMCwweDAxLDB4MDAsMHgwMCwweDAwCg' in text:
        return True
    if 'MHg0RCwweDVBLDB4ODAsMHgwMCwweDAxLDB4MDAsMHgwMCwweDAwCg' in text:
        return True
    if 'MHg0ZCwweDVhLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg' in text:
        return True
    if 'MHg0RCwweDVBLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg' in text:
        return True
    if 'MHg0ZCwweDVhLDB4ZTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDViCg' in text:
        return True
    if 'MHg0RCwweDVBLDB4RTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDVCCg' in text:
        return True


def hexbin_find(text):
    if '303130303131303130313031313031303030303030303030303030303030303030303030303030303030303030303030' in text:
        return True
    if '303130303131303130313031313031303031303030303031303130313030313030313031303130313031303031303030' in text:
        return True
    if '303130303131303130313031313031303031303130303030303030303030303030303030303031303030303030303030' in text:
        return True
    if '303130303131303130313031313031303130303030303030303030303030303030303030303030313030303030303030' in text:
        return True
    if '303130303131303130313031313031303130303130303030303030303030303030303030303031313030303030303030' in text:
        return True
    if '303130303131303130313031313031303131313031303030303030303030303030303030303030303030303030303030' in text:
        return True
    if '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30' in text:
        return True
    if '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 30 31 30 30 30 30 30 31 30 31 30 31 30 30 31 30 30 31 30 31 30 31 30 31 30 31 30 30 31 30 30 30' in text:
        return True
    if '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 30 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30 30' in text:
        return True
    if '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30' in text:
        return True
    if '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 31 30 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 31 30 30 30 30 30 30 30 30' in text:
        return True
    if '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 31 31 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30' in text:
        return True


def basebin_find(text):
    if 'MDEwMDExMDEwMTAxMTAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw' in text:
        return True
    if 'MDEwMDExMDEwMTAxMTAxMDAxMDAwMDAxMDEwMTAwMTAwMTAxMDEwMTAxMDAxMDAw' in text:
        return True
    if 'MDEwMDExMDEwMTAxMTAxMDAxMDEwMDAwMDAwMDAwMDAwMDAwMDAxMDAwMDAwMDAw' in text:
        return True
    if 'MDEwMDExMDEwMTAxMTAxMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTAwMDAwMDAw' in text:
        return True
    if 'MDEwMDExMDEwMTAxMTAxMDEwMDEwMDAwMDAwMDAwMDAwMDAwMDAxMTAwMDAwMDAw' in text:
        return True
    if 'MDEwMDExMDEwMTAxMTAxMDExMTAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw' in text:
        return True
    if 'MDEwMCAxMTAxIDAxMDEgMTAxMCAwMDAwIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAwMCAwMDAwIDAw' in text:
        return True
    if 'MDEwMCAxMTAxIDAxMDEgMTAxMCAwMTAwIDAwMDEgMDEwMSAwMDEwIDAxMDEgMDEwMSAwMTAwIDEw' in text:
        return True
    if 'MDEwMCAxMTAxIDAxMDEgMTAxMCAwMTAxIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAxMCAwMDAwIDAw' in text:
        return True
    if 'MDEwMCAxMTAxIDAxMDEgMTAxMCAxMDAwIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAwMSAwMDAwIDAw' in text:
        return True
    if 'MDEwMCAxMTAxIDAxMDEgMTAxMCAxMDAxIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAxMSAwMDAwIDAw' in text:
        return True
    if 'MDEwMCAxMTAxIDAxMDEgMTAxMCAxMTEwIDEwMDAgMDAwMCAwMDAwIDAwMDAgMDAwMCAwMDAwIDAw' in text:
        return True
    if 'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMD' in text:
        return True
    if 'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMDEgMDAgMDAgMDEgMDEgMDEgMDAgMTAgMDEgMDEgMDEgMDEgMDEgMDAgMTAgMD' in text:
        return True
    if 'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMDEgMDEgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMTAgMDAgMDAgMDAgMD' in text:
        return True
    if 'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMTAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDEgMDAgMDAgMDAgMD' in text:
        return True
    if 'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMTAgMDEgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMTEgMDAgMDAgMDAgMD' in text:
        return True
    if 'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMTEgMTAgMTAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMD' in text:
        return True


def basegzip_find(text):
    if 'H4sIAAAAAAAEAO18' in text:
        return True
    if 'H4sIAAAAAAAEAO19' in text:
        return True
    if 'H4sIAAAAAAAEAOy9' in text:
        return True
    if 'H4sIAAAAAAAEAO29' in text:
        return True
    if 'H4sIAAAAAAAEAOS9' in text:
        return True
    if 'H4sIAAAAAAAEAOy8' in text:
        return True
    if 'H4sIAAAAAAAEAOx9' in text:
        return True
    if 'H4sIAAAAAAAEAO17' in text:
        return True
    if 'H4sIAAAAAAAEAMy9' in text:
        return True


def baserot_find(text):
    if 'GIdDNNZNNNNRNNNN' in text:
        return True
    if 'GIcDNNVNNNNRNN8N' in text:
        return True
    if 'GIbNNNNNNNNNNNNN' in text:
        return True
    if 'GIcOHyIVvrIVtrjt' in text:
        return True
    if 'GIdNNNRNNNNRNONN' in text:
        return True
    if 'GIebNNNNNSgFEIJW' in text:
        return True
    if 'GIdDNNZNONNNNNNN' in text:
        return True
    if 'GIcOHyIVvrIVtrjtNNNN' in text:
        return True


def base64_doc(text):
    # application/msword or application/vnd.ms-excel
    if '0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAA' in text:
        return True
    # application/vnd.openxmlformats-officedocument.*
    if 'UEsDBBQABgAIAAAAIQ' in text:
        return True
    if 'UEsDBBQACAAIAAAAAA' in text:
        return True
    # text/rtf
    if 'e1xydGYxXGFkZWZsYW5nMTAy' in text:
        return True
    if 'e1xydGYxXGFuc2lcYW5zaWNw' in text:
        return True
    if 'e1xydGYxB25zaQduc2ljcGcx' in text:
        return True
    if 'e1xydGYxDQogSGVyZSBhcmUg' in text:
        return True
    if 'e1xydGYxe1xvYmplY3Rcb2Jq' in text:
        return True
    if 'e1xydGZ7XG9iamVjdFxvYmpo' in text:
        return True


def gzencode_find(text):
    if '7b0HYBxJliUmL23K' in text:
        return True
    if 'cG93ZXJzaGVsbC' in text:
        return True
    if 'UG93ZXJTaGVsbC' in text:
        return True


def basethreetwelve_find(text):
    if '396 398 425 393 377 377 389 377 377 377 377 381 377 377 377 377' in text:
        return True
    if '396 398 424 393 377 377 385 377 377 377 377 381 377 377 368 377' in text:
        return True
    if '396 398 423 377 377 377 377 377 377 377 377 377 377 377 377 377' in text:
        return True
    if '396 398 424 378 397 420 398 385 417 413 398 385 415 413 431 415' in text:
        return True
    if '396 398 425 377 377 377 381 377 377 377 377 381 377 378 377 377' in text:
        return True
    if '396 398 426 423 377 377 377 377 377 382 428 395 394 398 399 386' in text:
        return True
    if '396 398 425 393 377 377 389 377 378 377 377 377 377 377 377 377' in text:
        return True
    if '396 398 424 378 397 420 398 385 417 413 398 385 415 413 431 415 377 377 377 377' in text:
        return True
    if '419 386 379 393 419 381 361 409 393 398 386 398 395 385 422 420 395 385 384 427 385 377 377 377 377' in text:
        return True


def basebash_find(text):
    if 'IyEvYmluL2Jhc2' in text:
        return True
    if 'IyEvYmluL3No' in text:
        return True
    if 'L2Jpbi9iYXNo' in text:
        return True
    if 'L2Jpbi9za' in text:
        return True
    if 'IyEgL3Vzci9iaW4vZW52IHB5dGhvb' in text:
        return True
    if 'IyEvdXNyL2Jpbi9lbnYgcHl0aG9' in text:
        return True
    if 'IyEvdXNyL2Jpbi9weXRob2' in text:
        return True


def save_file(text, detect_type, key):
    print('%s: %s' % (detect_type, key))
    outfile = pastes_dir + key + "." + detect_type
    if not os.path.exists(outfile):
        f = open(outfile, 'w')
        f.write(text)
        f.close()
        return
    else:
        print("paste already exists: " + outfile)
        return


def save_raw(text, key):
    rawfile = originals_dir + key
    if not os.path.exists(rawfile):
        f = open(rawfile, 'w')
        f.write(text)
        f.close()
        return
    else:
        print("paste already exists: " + rawfile)
        return


# The line below would be a more elegant way to build a function list,
# but it doesn't work and you can't control order for performance
# find_functions = [f for f in dir() if f[0] is not '_' and f.endswith('_find')]

find_functions = [base64_find, basebash_find, gzencode_find, basegzip_find,
                  basebin_find, basehex_find, baserot_find, bin_find,
                  basethreetwelve_find, dec_find, doublebase_find,
                  doublewidebase_find, exe_find, gzencode_find, hexbase_find,
                  hexbin_find, posh_find, hex_find]
params = {'limit': limit}
r = requests.get(url_pastebin_scraping, params)
try:
    response = r.json()
except json.decoder.JSONDecodeError:
    print('JSONDecodeError')
    print('raw response from ' + url_pastebin_scraping + ': ' + r.content)
    sys.exit(1)
logfile = open(logfile, 'a+')
counter = 0
byte_counter = 0
for paste in response:
    title = paste["title"]
    syntax = paste["syntax"]
    expire = paste["expire"]
    user = paste["user"]
    key = paste["key"]
    date = paste["date"]
    size = int(paste["size"])
    if not os.path.exists(originals_dir + key):
        if any(user.lower() == username.lower() for username in userlist):
            detect_type = "user_" + user
            save_file(r.content, detect_type, key)
            save_raw(r.content, key)
            logentry = {
                'paste':str(key),
                'type':str(detect_type),
                'title':str(title),
                'user':str(user),
                'syntax':str(syntax),
                'date':str(date),
                'expiration':str(expire),
            }
            jlo = json.dumps(logentry)
            logfile.write(jlo + '\n')
            break
        if (size > min_size):
            counter += 1
            byte_counter += size
            url = paste["scrape_url"]
            r = requests.get(url)
            forward_text = r.content
            reverse_text = forward_text[::-1]
            for fn in find_functions:
                if fn(forward_text):
                    detect_type = str(fn).split('_')[0].split(' ')[1]
                    save_file(forward_text, detect_type, key)
                    save_raw(forward_text, key)
                    logentry = {
                        'paste':str(key),
                        'type':str(detect_type),
                        'title':str(title),
                        'user':str(user),
                        'syntax':str(syntax),
                        'date':str(date),
                        'expiration':str(expire)
                    }
                    jlo = json.dumps(logentry)
                    logfile.write(jlo + '\n')
                    break
                if fn(reverse_text):
                    detect_type = str(fn).split('_')[0].split(' ')[1]
                    save_file(reverse_text, detect_type, key)
                    save_raw(forward_text, key)
                    logentry = {
                        'paste':str(key),
                        'type':str(detect_type),
                        'title':str(title),
                        'user':str(user),
                        'syntax':str(syntax),
                        'date':str(date),
                        'expiration':str(expire)
                    }
                    jlo = json.dumps(logentry)
                    logfile.write(jlo + '\n')
                    break

end = time.time()
print("documents read: " + str(counter))
print("bytes scanned: " + str(byte_counter))
print("run time: " + str(end - start))
