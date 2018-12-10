import string
from binascii import *

import pefile

from common import Modules, load_yara_rules, PEParseModule, ModuleMetadata
from types import StringType

class darkcomet(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="darkcomet",
            bot_name="DarkComet",
            description="RAT",
            authors=["Brian Wallace (@botnet_hunter)", "Kevin Breen <kevin@techanarchy.net>"],
            version="1.0.1",
            date="Oct 04, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("darkcomet.yara")
        return self.yara_rules

    @staticmethod
    def rc4crypt(data, key):
        x = 0
        box = range(256)
        for i in range(256):
            x = (x + box[i] + ord(key[i % len(key)])) % 256
            box[i], box[x] = box[x], box[i]
        x = 0
        y = 0
        out = []
        for char in data:
            x = (x + 1) % 256
            y = (y + box[x]) % 256
            box[x], box[y] = box[y], box[x]
            out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

        return ''.join(out)

    @staticmethod
    def v51_data(data, enckey):
        config = {"FWB": "", "GENCODE": "", "MUTEX": "", "NETDATA": "", "OFFLINEK": "", "SID": "", "FTPUPLOADK": "",
                  "FTPHOST": "", "FTPUSER": "", "FTPPASS": "", "FTPPORT": "", "FTPSIZE": "", "FTPROOT": "", "PWD": ""}
        dec = darkcomet.rc4crypt(unhexlify(data), enckey)
        dec_list = dec.split('\n')
        for entries in dec_list[1:-1]:
            key, value = entries.split('=')
            key = key.strip()
            value = value.rstrip()[1:-1]
            clean_value = filter(lambda x: x in string.printable, value)
            config[key] = clean_value
            config["Version"] = enckey[:-4]
        return config

    @staticmethod
    def v3_data(data, key):
        config = {"FWB": "", "GENCODE": "", "MUTEX": "", "NETDATA": "", "OFFLINEK": "", "SID": "", "FTPUPLOADK": "",
                  "FTPHOST": "", "FTPUSER": "", "FTPPASS": "", "FTPPORT": "", "FTPSIZE": "", "FTPROOT": "", "PWD": ""}
        dec = darkcomet.rc4crypt(unhexlify(data), key)
        config[str(entry.name)] = dec
        config["Version"] = enckey[:-4]

        return config

    @staticmethod
    def versionCheck(rawData):
        if "#KCMDDC2#" in rawData:
            return "#KCMDDC2#-890"

        elif "#KCMDDC4#" in rawData:
            return "#KCMDDC4#-890"

        elif "#KCMDDC42#" in rawData:
            return "#KCMDDC42#-890"

        elif "#KCMDDC42F#" in rawData:
            return "#KCMDDC42F#-890"

        elif "#KCMDDC5#" in rawData:
            return "#KCMDDC5#-890"

        elif "#KCMDDC51#" in rawData:
            return "#KCMDDC51#-890"
        else:
            return None

    @staticmethod
    def configExtract(rawData, key):
        config = {"FWB": "", "GENCODE": "", "MUTEX": "", "NETDATA": "", "OFFLINEK": "", "SID": "", "FTPUPLOADK": "", "FTPHOST": "", "FTPUSER": "", "FTPPASS": "", "FTPPORT": "", "FTPSIZE": "", "FTPROOT": "", "PWD": ""}

        pe = pefile.PE(data=rawData)
        rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "DCDATA":

                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                config = darkcomet.v51_data(data, key)

            elif str(entry.name) in config.keys():

                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                dec = darkcomet.rc4crypt(unhexlify(data), key)
                config[str(entry.name)] = filter(lambda x: x in string.printable, dec)
                config["Version"] = key[:-4]
        return config

    @staticmethod
    def run(data):
        versionKey = darkcomet.versionCheck(data)
        if versionKey != None:
            config = darkcomet.configExtract(data, versionKey)

            return config
        else:
            return None

    def get_bot_information(self, file_data):
        results = darkcomet.run(file_data)

        # Sanitize
        for key in results.keys():
            if type(results[key]) is StringType:
                results[key] = results[key].encode("string-escape")

        if "NETDATA" in results and len(results["NETDATA"]) > 0:
            c2s = results["NETDATA"].split("|")
            results['c2s'] = []
            for c2 in c2s:
                results['c2s'].append({"c2_uri": "tcp://" + c2 + "/"})
        return results


Modules.list.append(darkcomet())