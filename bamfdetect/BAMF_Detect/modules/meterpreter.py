from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata
from string import ascii_lowercase, ascii_uppercase, digits
import re
import socket
import struct

class meterpreterx86(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="meterpreterx86",
            bot_name="Meterpreter x86 Shellcode Payload",
            description="Shellcode Loader",
            authors="Paul Melson (@pmelson)",
            version="1.0",
            date="January 22, 2019",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("meterpreterx86.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        REVTCPSHELLCODE32 = re.compile('fce8820000006089(.*)00ffd56a(0a|01)68([0-9a-f]{8})680200([0-9a-f]{4})89e65050', re.IGNORECASE)
        hexbytes = file_data.encode('hex')
        try:
            ipbytes = REVTCPSHELLCODE32.search(hexbytes)
            ipaddr = int("".join([ipbytes.group(3)[i-2:i] for i in range(8,0,-2)]), 16)
            ip = socket.inet_ntoa(struct.pack("<L", ipaddr))
            port = int(ipbytes.group(4), 16)
            c2 = "{0}:{1}".format(ip,port)
        except:
            ip = ""
            port = ""
        if ip != "":
            results['c2_uri'] = "tcp://{0}:{1}".format(ip,port)

        return results


Modules.list.append(meterpreterx86())
