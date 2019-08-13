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

# compile regular expression for hex_find function
HEX_PE = re.compile('[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|41|50|80|90|e8)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|52)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|01|02|03|55)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|48)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|04|89)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|5b|e5)')

# list of suspicious accounts to track no matter what they post
# this should spin out into its own project
userlist = ['pmelson']


def posh_find(text):
    # make term searches case insensitive
    txtlower = text.lower()
    posh_search_terms = ['/c"powershell', '/c powershell', 'powershell -',
                         'powershell /', 'powershell.exe -', '\1.0\powershell.exe',
                         '\\1.0\\powershell.exe', '-runas32', '::createthread',
                         ' -bxor', '[system.convert]::', 'frombase64string(',
                         'new-object system.io.', '[system.net.',
                         'system.reflection.assemblyname',
                         'x509enrollment.cbinaryconverter',
                         'convertto-securestring']
    for term in posh_search_terms:
        if term in txtlower:
            return True
    # base64 searches are case sensitive
    posh_base64_terms = ['93ZXJzaGVsb', 'd2Vyc2hlbGw', 'dlcnNoZWxs',
                         '8Ad2UAcnMAaGUAbG', 'b3cAZXIAc2gAZWw',
                         '8Ad2UAcnMAaGUAbG', '93ZXJTaGVsb', 'd2VyU2hlbG',
                         '3dlclNoZWx', '8Ad2UAclMAaGUAbG', '3cAZXIAU2gAZWw',
                         'N5c3RlbS5Db252ZXJ0XT', 'eXN0ZW0uQ29udmVydF06O',
                         'lzdGVtLkNvbnZlcnRdO', 'MAeXMAdGUAbS4AQ28AbnYAZXIAdF0AO',
                         'AHlzAHRlAG0uAENvAG52AGVyAHRdAD',
                         'B5cwB0ZQBtLgBDbwBudgBlcgB0XQ', 'JvbUJhc2U2N',
                         'b21CYXNlNj', 'cm9tQmFzZTY', 'IAb20AQmEAc2UAN',
                         'AG9tAEJhAHNlADY0', 'gBvbQBCYQBzZQA2',
                         'V3LU9iamVjdCBTeXN0ZW0uSU', 'ldy1PYmplY3QgU3lzdGVtLklP',
                         'ZXctT2JqZWN0IFN5c3RlbS5JT',
                         'UAdy0AT2IAamUAY3QAIFMAeXMAdGUAbS4ASU8',
                         'lAHctAE9iAGplAGN0ACBTAHlzAHRlAG0uAElPA',
                         'ZQB3LQBPYgBqZQBjdAAgUwB5cwB0ZQBtLgBJ', 'N5c3RlbS5OZX',
                         'TeXN0ZW0uTmV0', 'U3lzdGVtLk5ld', 'MAeXMAdGUAbS4ATmUAd',
                         'TAHlzAHRlAG0uAE5lAH', 'UwB5cwB0ZQBtLgBOZQB0',
                         'lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHlO',
                         '5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5TmFt',
                         'XN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseU5hb',
                         'kAc3QAZW0ALlIAZWYAbGUAY3QAaW8Abi4AQXMAc2UAbWIAbHkATmE',
                         '5AHN0AGVtAC5SAGVmAGxlAGN0AGlvAG4uAEFzAHNlAG1iAGx5AE5hAG',
                         'QBzdABlbQAuUgBlZgBsZQBjdABpbwBuLgBBcwBzZQBtYgBseQBOYQBt',
                         'pDcmVhdGVUaHJlY', '6Q3JlYXRlVGhyZW', 'kNyZWF0ZVRocmVh',
                         'oAQ3IAZWEAdGUAVGgAcmUAY', 'AENyAGVhAHRlAFRoAHJlAG',
                         'gBDcgBlYQB0ZQBUaAByZQB',
                         'UwOUVucm9sbG1lbnQuQ0JpbmFyeUNvbnZlcnR',
                         '1MDlFbnJvbGxtZW50LkNCaW5hcnlDb252ZXJ0Z',
                         'NTA5RW5yb2xsbWVudC5DQmluYXJ5Q29udmVydG',
                         'UAMDkARW4Acm8AbGwAbWUAbnQALkMAQmkAbmEAcnkAQ28AbnYAZXIAdG',
                         '1ADA5AEVuAHJvAGxsAG1lAG50AC5DAEJpAG5hAHJ5AENvAG52AGVyAHR',
                         'NQAwOQBFbgBybwBsbABtZQBudAAuQwBCaQBuYQByeQBDbwBudgBlcgB0',
                         '9udmVydFRvLVNlY3VyZVN0cmlu', 'vbnZlcnRUby1TZWN1cmVTdHJpb',
                         'b252ZXJ0VG8tU2VjdXJlU3RyaW',
                         '8AbnYAZXIAdFQAby0AU2UAY3UAcmUAU3QAcmkAb',
                         'vAG52AGVyAHRUAG8tAFNlAGN1AHJlAFN0AHJpAG',
                         'bwBudgBlcgB0VABvLQBTZQBjdQByZQBTdAByaQB', 'IC1ieG9y',
                         'AtYnhvcg', 'LWJ4b3I', 'IC0AYngAb3', 'tAGJ4AG9y',
                         'LQBieABvc']
    for term in posh_base64_terms:
        if term in text:
            return True


def dec_find(text):
    dec_search_terms = ['77 90 144 0 3 0 4 0', '77 90 232 0 0 0 0 91',
                        '77 90 144 0 3 0 0 0', '77 90 80 0 2 0 0 0',
                        '77 90 0 0 0 0 0 0', '77 90 65 82 85 72 137 229',
                        '77 90 128 0 1 0 0 0', '77,90,144,0,3,0,4,0,',
                        '77,90,232,0,0,0,0,91,', '77,90,144,0,3,0,0,0,',
                        '77,90,80,0,2,0,0,0,', '77,90,0,0,0,0,0,0,',
                        '77,90,65,82,85,72,137,229,', '77,90,128,0,1,0,0,0,',
                        '77, 90, 144, 0, 3, 0, 4, 0,',
                        '77, 90, 232, 0, 0, 0, 0, 91,',
                        '77, 90, 144, 0, 3, 0, 0, 0,',
                        '77, 90, 80, 0, 2, 0, 0, 0,',
                        '77, 90, 0, 0, 0, 0, 0, 0,',
                        '77, 90, 65, 82, 85, 72, 137, 229,',
                        '77, 90, 128, 0, 1, 0, 0, 0,']
    for term in dec_search_terms:
        if term in text:
            return True


def bin_find(text):
    bin_search_terms = ['010011010101101000000000000000000000000000000000',
                        '010011010101101001000001010100100101010101001000',
                        '010011010101101001010000000000000000001000000000',
                        '010011010101101010000000000000000000000100000000',
                        '010011010101101010010000000000000000001100000000',
                        '010011010101101011101000000000000000000000000000',
                        '0100 1101 0101 1010 0000 0000 0000 0000 0000 0000 0000 0000',
                        '0100 1101 0101 1010 0100 0001 0101 0010 0101 0101 0100 1000',
                        '0100 1101 0101 1010 0101 0000 0000 0000 0000 0010 0000 0000',
                        '0100 1101 0101 1010 1000 0000 0000 0000 0000 0001 0000 0000',
                        '0100 1101 0101 1010 1001 0000 0000 0000 0000 0011 0000 0000',
                        '0100 1101 0101 1010 1110 1000 0000 0000 0000 0000 0000 0000',
                        '01 00 11 01 01 01 10 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                        '01 00 11 01 01 01 10 10 01 00 00 01 01 01 00 10 01 01 01 01 01 00 10 00',
                        '01 00 11 01 01 01 10 10 01 01 00 00 00 00 00 00 00 00 00 10 00 00 00 00',
                        '01 00 11 01 01 01 10 10 10 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00',
                        '01 00 11 01 01 01 10 10 10 01 00 00 00 00 00 00 00 00 00 11 00 00 00 00',
                        '01 00 11 01 01 01 10 10 11 10 10 00 00 00 00 00 00 00 00 00 00 00 00 00']
    for term in bin_search_terms:
        if term in text:
            return True


def base64_find(text):
    base64_search_terms = ['TVqQAAMAAAAEAAAA', 'TVpQAAIAAAAEAA8A',
                           'TVoAAAAAAAAAAAAA', 'TVpBUlVIieVIgewg',
                           'TVqAAAEAAAAEABAA', 'TVroAAAAAFtSRVWJ',
                           'TVqQAAMABAAAAAAA', 'TVpBUlVIieVIgewgAAAA',
                           'kJCQkE1aQVJVSInlSIHsIAAAA', 'pcyBwcm9ncm']
    for term in base64_search_terms:
        if term in text:
            return True


def doublebase_find(text):
    double_search_terms = ['VFZxUUFBTUFBQUFFQUFBQ', 'VFZwUUFBSUFBQUFFQUE4Q',
                           'VFZvQUFBQUFBQUFBQUFBQ', 'VFZwQlVsVklpZVZJZ2V3Z',
                           'VFZxQUFBRUFBQUFFQUJBQ', 'VFZyb0FBQUFBRnRTUlZXS',
                           'VFZxUUFBTUFCQUFBQUFBQ']
    for term in double_search_terms:
        if term in text:
            return True


def doublewidebase_find(text):
    doublewide_search_terms = ['VABWAHEAUQBBAEEATQBBAEEAQQBBAEUAQQBBAEEAQQ',
                               'VABWAHAAUQBBAEEASQBBAEEAQQBBAEUAQQBBADgAQQ',
                               'VABWAG8AQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQ',
                               'VABWAHAAQgBVAGwAVgBJAGkAZQBWAEkAZwBlAHcAZw',
                               'VABWAHEAQQBBAEEARQBBAEEAQQBBAEUAQQBCAEEAQQ',
                               'VABWAHIAbwBBAEEAQQBBAEEARgB0AFMAUgBWAFcASg',
                               'VABWAHEAUQBBAEEATQBBAEIAQQBBAEEAQQBBAEEAQQ',
                               'VABWAHAAQgBVAGwAVgBJAGkAZQBWAEkAZwBlAHcAZwBBAEEAQQ',
                               'awBKAEMAUQBrAEUAMQBhAFEAVgBKAFYAUwBJAG4AbABTAEkASABzAEkAQQBBAEEAQQ']
    for term in doublewide_search_terms:
        if term in text:
            return True


def exe_find(text):
    exe_search_terms = ['\x4d\x5a\x90\x00\x03\x00\x00\x00',
                        '\x4d\x5a\x50\x00\x02\x00\x00\x00',
                        '\x4d\x5a\x00\x00\x00\x00\x00\x00',
                        '\x4d\x5a\x41\x52\x55\x48\x89\xe5',
                        '\x4d\x5a\x80\x00\x01\x00\x00\x00',
                        '\x4d\x5a\x90\x00\x03\x00\x04\x00',
                        '\x4d\x5a\xe8\x00\x00\x00\x00\x5b']
    for term in exe_search_terms:
        if term in text:
            return True


def hex_find(text):
    txtlower = text.lower()
    hex_search_terms = ['4d5a900003000000', '4d5a500002000000',
                        '4d5a000000000000', '4d5a4152554889e5',
                        '4d5a800001000000', '4d5a900003000400',
                        '4d5ae8000000005b']
    for term in hex_search_terms:
        if term in txtlower:
            return True
    if HEX_PE.search(txtlower):
        return True


def hexbase_find(text):
    txtlower = text.lower()
    hexbase_search_terms = ['5456715141414d414141414541414141',
                            '54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41',
                            '54567051414149414141414541413841',
                            '54 56 70 51 41 41 49 41 41 41 41 45 41 41 38 41',
                            '54566f41414141414141414141414141',
                            '54 56 6f 41 41 41 41 41 41 41 41 41 41 41 41 41',
                            '54567042556c56496965564967657767',
                            '54 56 70 42 55 6c 56 49 69 65 56 49 67 65 77 67',
                            '54567141414145414141414541424141',
                            '54 56 71 41 41 41 45 41 41 41 41 45 41 42 41 41',
                            '5456726f41414141414674535256574a',
                            '54 56 72 6f 41 41 41 41 41 46 74 53 52 56 57 4a',
                            '5456715141414d414241414141414141',
                            '54 56 71 51 41 41 4d 41 42 41 41 41 41 41 41 41']
    for term in hexbase_search_terms:
        if term in txtlower:
            return True


def basehex_find(text):
    basehex_search_terms = ['NGQ1YTkwMDAwMzAwMDAwMA', 'NEQ1QTkwMDAwMzAwMDAwMA',
                            'NGQ1YTUwMDAwMjAwMDAwMA', 'NEQ1QTUwMDAwMjAwMDAwMA',
                            'NGQ1YTAwMDAwMDAwMDAwMA', 'NEQ1QTAwMDAwMDAwMDAwMA',
                            'NGQ1YTQxNTI1NTQ4ODllNQ', 'NEQ1QTQxNTI1NTQ4ODlFNQ',
                            'NGQ1YTgwMDAwMTAwMDAwMA', 'NEQ1QTgwMDAwMTAwMDAwMA',
                            'NGQ1YTkwMDAwMzAwMDQwMA', 'NEQ1QTkwMDAwMzAwMDQwMA',
                            'NGQ1YWU4MDAwMDAwMDA1Yg', 'NEQ1QUU4MDAwMDAwMDA1Qg',
                            'NGQgNWEgOTAgMDAgMDMgMDAgMDQgMDA',
                            'NEQgNUEgOTAgMDAgMDMgMDAgMDQgMDA',
                            'NGQgNWEgZTggMDAgMDAgMDAgMDAgNWI',
                            'NEQgNUEgRTggMDAgMDAgMDAgMDAgNUI',
                            'NGQgNWEgOTAgMDAgMDMgMDAgMDAgMDA',
                            'NEQgNUEgOTAgMDAgMDMgMDAgMDAgMDA',
                            'NGQgNWEgNTAgMDAgMDIgMDAgMDAgMDA',
                            'NEQgNUEgNTAgMDAgMDIgMDAgMDAgMDA',
                            'NGQgNWEgMDAgMDAgMDAgMDAgMDAgMDA',
                            'NEQgNUEgMDAgMDAgMDAgMDAgMDAgMDA',
                            'NGQgNWEgNDEgNTIgNTUgNDggODkgZTU',
                            'NEQgNUEgNDEgNTIgNTUgNDggODkgRTU',
                            'NGQgNWEgODAgMDAgMDEgMDAgMDAgMDA',
                            'NEQgNUEgODAgMDAgMDEgMDAgMDAgMDA',
                            'NGQgNWEgOTAgMDAgMDMgMDAgMDQgMDA',
                            'NEQgNUEgOTAgMDAgMDMgMDAgMDQgMDA',
                            'NGQgNWEgZTggMDAgMDAgMDAgMDAgNWI',
                            'NEQgNUEgRTggMDAgMDAgMDAgMDAgNUI',
                            'MHg0ZCwweDVhLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg',
                            'MHg0RCwweDVBLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg',
                            'MHg0ZCwweDVhLDB4ZTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDViCg',
                            'MHg0RCwweDVBLDB4RTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDVCCg',
                            'MHg0ZCwweDVhLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwMCwweDAwCg',
                            'MHg0RCwweDVBLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwMCwweDAwCg',
                            'MHg0ZCwweDVhLDB4NTAsMHgwMCwweDAyLDB4MDAsMHgwMCwweDAwCg',
                            'MHg0RCwweDVBLDB4NTAsMHgwMCwweDAyLDB4MDAsMHgwMCwweDAwCg',
                            'MHg0ZCwweDVhLDB4MDAsMHgwMCwweDAwLDB4MDAsMHgwMCwweDAwCg',
                            'MHg0RCwweDVBLDB4MDAsMHgwMCwweDAwLDB4MDAsMHgwMCwweDAwCg',
                            'MHg0ZCwweDVhLDB4NDEsMHg1MiwweDU1LDB4NDgsMHg4OSwweGU1Cg',
                            'MHg0RCwweDVBLDB4NDEsMHg1MiwweDU1LDB4NDgsMHg4OSwweEU1Cg',
                            'MHg0ZCwweDVhLDB4ODAsMHgwMCwweDAxLDB4MDAsMHgwMCwweDAwCg',
                            'MHg0RCwweDVBLDB4ODAsMHgwMCwweDAxLDB4MDAsMHgwMCwweDAwCg',
                            'MHg0ZCwweDVhLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg',
                            'MHg0RCwweDVBLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg',
                            'MHg0ZCwweDVhLDB4ZTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDViCg',
                            'MHg0RCwweDVBLDB4RTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDVCCg']
    for term in basehex_search_terms:
        if term in text:
            return True


def hexbin_find(text):
    hexbin_search_terms = ['303130303131303130313031313031303030303030303030303030303030303030303030303030303030303030303030',
                           '303130303131303130313031313031303031303030303031303130313030313030313031303130313031303031303030',
                           '303130303131303130313031313031303031303130303030303030303030303030303030303031303030303030303030',
                           '303130303131303130313031313031303130303030303030303030303030303030303030303030313030303030303030',
                           '303130303131303130313031313031303130303130303030303030303030303030303030303031313030303030303030',
                           '303130303131303130313031313031303131313031303030303030303030303030303030303030303030303030303030',
                           '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30',
                           '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 30 31 30 30 30 30 30 31 30 31 30 31 30 30 31 30 30 31 30 31 30 31 30 31 30 31 30 30 31 30 30 30',
                           '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 30 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30 30',
                           '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30',
                           '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 31 30 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 31 30 30 30 30 30 30 30 30',
                           '30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 31 31 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30']
    for term in hexbin_search_terms:
        if term in text:
            return True


def basebin_find(text):
    basebin_search_terms = ['MDEwMDExMDEwMTAxMTAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw',
                            'MDEwMDExMDEwMTAxMTAxMDAxMDAwMDAxMDEwMTAwMTAwMTAxMDEwMTAxMDAxMDAw',
                            'MDEwMDExMDEwMTAxMTAxMDAxMDEwMDAwMDAwMDAwMDAwMDAwMDAxMDAwMDAwMDAw',
                            'MDEwMDExMDEwMTAxMTAxMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTAwMDAwMDAw',
                            'MDEwMDExMDEwMTAxMTAxMDEwMDEwMDAwMDAwMDAwMDAwMDAwMDAxMTAwMDAwMDAw',
                            'MDEwMDExMDEwMTAxMTAxMDExMTAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw',
                            'MDEwMCAxMTAxIDAxMDEgMTAxMCAwMDAwIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAwMCAwMDAwIDAw',
                            'MDEwMCAxMTAxIDAxMDEgMTAxMCAwMTAwIDAwMDEgMDEwMSAwMDEwIDAxMDEgMDEwMSAwMTAwIDEw',
                            'MDEwMCAxMTAxIDAxMDEgMTAxMCAwMTAxIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAxMCAwMDAwIDAw',
                            'MDEwMCAxMTAxIDAxMDEgMTAxMCAxMDAwIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAwMSAwMDAwIDAw',
                            'MDEwMCAxMTAxIDAxMDEgMTAxMCAxMDAxIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAxMSAwMDAwIDAw',
                            'MDEwMCAxMTAxIDAxMDEgMTAxMCAxMTEwIDEwMDAgMDAwMCAwMDAwIDAwMDAgMDAwMCAwMDAwIDAw',
                            'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMD',
                            'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMDEgMDAgMDAgMDEgMDEgMDEgMDAgMTAgMDEgMDEgMDEgMDEgMDEgMDAgMTAgMD',
                            'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMDEgMDEgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMTAgMDAgMDAgMDAgMD',
                            'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMTAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDEgMDAgMDAgMDAgMD',
                            'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMTAgMDEgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMTEgMDAgMDAgMDAgMD',
                            'MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMTEgMTAgMTAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMD']
    for term in basebin_search_terms:
        if term in text:
            return True


def basegzip_find(text):
    basegzip_search_terms = ['H4sIAAAAAAAEAO18', 'H4sIAAAAAAAEAO19',
                             'H4sIAAAAAAAEAOy9', 'H4sIAAAAAAAEAO29',
                             'H4sIAAAAAAAEAOS9', 'H4sIAAAAAAAEAOy8',
                             'H4sIAAAAAAAEAOx9', 'H4sIAAAAAAAEAO17',
                             'H4sIAAAAAAAEAMy9']
    for term in basegzip_search_terms:
        if term in text:
            return True


def baserot_find(text):
    baserot_search_terms = ['GIdDNNZNNNNRNNNN', 'GIcDNNVNNNNRNN8N',
                            'GIbNNNNNNNNNNNNN', 'GIcOHyIVvrIVtrjt',
                            'GIdNNNRNNNNRNONN', 'GIebNNNNNSgFEIJW',
                            'GIdDNNZNONNNNNNN', 'GIcOHyIVvrIVtrjtNNNN']
    for term in baserot_search_terms:
        if term in text:
            return True


def base64_doc(text):
    basedoc_search_terms = ['0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAA',
                            'UEsDBBQABgAIAAAAIQ',
                            'UEsDBBQACAAIAAAAAA',
                            'e1xydGYxXGFkZWZsYW5nMTAy',
                            'e1xydGYxXGFuc2lcYW5zaWNw',
                            'e1xydGYxB25zaQduc2ljcGcx',
                            'e1xydGYxDQogSGVyZSBhcmUg',
                            'e1xydGYxe1xvYmplY3Rcb2Jq',
                            'e1xydGZ7XG9iamVjdFxvYmpo']
    for term in basedoc_search_terms:
        if term in text:
            return True


def gzencode_find(text):
    gzencode_search_terms = ['7b0HYBxJliUmL23K', 'cG93ZXJzaGVsbC',
                             'UG93ZXJTaGVsbC']
    for term in gzencode_search_terms:
        if term in text:
            return True


def basethreetwelve_find(text):
    base312_search_terms = ['396 398 425 393 377 377 389 377 377 377 377 381 377 377 377 377',
                            '396 398 424 393 377 377 385 377 377 377 377 381 377 377 368 377',
                            '396 398 423 377 377 377 377 377 377 377 377 377 377 377 377 377',
                            '396 398 424 378 397 420 398 385 417 413 398 385 415 413 431 415',
                            '396 398 425 377 377 377 381 377 377 377 377 381 377 378 377 377',
                            '396 398 426 423 377 377 377 377 377 382 428 395 394 398 399 386',
                            '396 398 425 393 377 377 389 377 378 377 377 377 377 377 377 377',
                            '396 398 424 378 397 420 398 385 417 413 398 385 415 413 431 415 377 377 377 377',
                            '419 386 379 393 419 381 361 409 393 398 386 398 395 385 422 420 395 385 384 427 385 377 377 377 377']
    for term in base312_search_terms:
        if term in text:
            return True


def basebash_find(text):
    basebash_search_terms = ['IyEvYmluL2Jhc2', 'IyEvYmluL3No', 'L2Jpbi9iYXNo',
                             'L2Jpbi9za', 'IyEgL3Vzci9iaW4vZW52IHB5dGhvb',
                             'IyEvdXNyL2Jpbi9lbnYgcHl0aG9',
                             'IyEvdXNyL2Jpbi9weXRob2']
    for term in basebash_search_terms:
        if term in text:
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
