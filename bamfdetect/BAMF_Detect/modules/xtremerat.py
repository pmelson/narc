from common import Modules, load_yara_rules, PEParseModule, ModuleMetadata
from struct import unpack
import pefile


class xtreme(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="xtreme",
            bot_name="Xtreme",
            description="RAT...TO THE EXTREME",
            authors=["kevthehermit"],  # https://github.com/kevthehermit/RATDecoders/blob/master/Xtreme.py
            version="1.0.0",
            date="March 25, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("xtreme.yara")
        return self.yara_rules

    @staticmethod
    def run(data):
        key = "C\x00O\x00N\x00F\x00I\x00G"
        codedConfig = xtreme.configExtract(data)
        if codedConfig is not None:
            rawConfig = xtreme.rc4crypt(codedConfig, key)
            if len(rawConfig) == 0xe10:
                config = None
            elif len(rawConfig) == 0x1390 or len(rawConfig) == 0x1392:
                config = xtreme.v29(rawConfig)
            elif len(rawConfig) == 0x5Cc:
                config = xtreme.v32(rawConfig)
            elif len(rawConfig) == 0x7f0:
                config = xtreme.v35(rawConfig)
            else:
                config = None
            return config
        else:
            return {}


    @staticmethod
    def rc4crypt(data, key):  # modified for bad implemented key length
        x = 0
        box = range(256)
        for i in range(256):
            x = (x + box[i] + ord(key[i % 6])) % 256
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
    def configExtract(rawData):
        try:
            pe = pefile.PE(data=rawData)
            try:
              rt_string_idx = [
              entry.id for entry in
              pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
            except ValueError, e:
                return None
            except AttributeError, e:
                return None
            rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
            for entry in rt_string_directory.directory.entries:
                if str(entry.name) == "XTREME":
                    data_rva = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
                    data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                    return data
        except:
            return None

    @staticmethod
    def v29(rawConfig):
        dict = {}
        dict["ID"] = xtreme.getUnicodeString(rawConfig, 0x9e0)
        dict["Group"] = xtreme.getUnicodeString(rawConfig, 0xa5a)
        dict["Version"] = xtreme.getUnicodeString(rawConfig, 0xf2e) # use this to recalc offsets
        dict["Mutex"] = xtreme.getUnicodeString(rawConfig, 0xfaa)
        dict["Install Dir"] = xtreme.getUnicodeString(rawConfig, 0xb50)
        dict["Install Name"] = xtreme.getUnicodeString(rawConfig, 0xad6)
        dict["HKLM"] = xtreme.getUnicodeString(rawConfig, 0xc4f)
        dict["HKCU"] = xtreme.getUnicodeString(rawConfig, 0xcc8)
        dict["Custom Reg Key"] = xtreme.getUnicodeString(rawConfig, 0xdc0)
        dict["Custom Reg Name"] = xtreme.getUnicodeString(rawConfig, 0xe3a)
        dict["Custom Reg Value"] = xtreme.getUnicodeString(rawConfig, 0xa82)
        dict["ActiveX Key"] = xtreme.getUnicodeString(rawConfig, 0xd42)
        dict["Injection"] = xtreme.getUnicodeString(rawConfig, 0xbd2)
        dict["FTP Server"] = xtreme.getUnicodeString(rawConfig, 0x111c)
        dict["FTP UserName"] = xtreme.getUnicodeString(rawConfig, 0x1210)
        dict["FTP Password"] = xtreme.getUnicodeString(rawConfig, 0x128a)
        dict["FTP Folder"] = xtreme.getUnicodeString(rawConfig, 0x1196)
        dict["Domain1"] = str(xtreme.getUnicodeString(rawConfig, 0x50)+":"+str(unpack("<I",rawConfig[0:4])[0]))
        dict["Domain2"] = str(xtreme.getUnicodeString(rawConfig, 0xca)+":"+str(unpack("<I",rawConfig[4:8])[0]))
        dict["Domain3"] = str(xtreme.getUnicodeString(rawConfig, 0x144)+":"+str(unpack("<I",rawConfig[8:12])[0]))
        dict["Domain4"] = str(xtreme.getUnicodeString(rawConfig, 0x1be)+":"+str(unpack("<I",rawConfig[12:16])[0]))
        dict["Domain5"] = str(xtreme.getUnicodeString(rawConfig, 0x238)+":"+str(unpack("<I",rawConfig[16:20])[0]))
        dict["Domain6"] = str(xtreme.getUnicodeString(rawConfig, 0x2b2)+":"+str(unpack("<I",rawConfig[20:24])[0]))
        dict["Domain7"] = str(xtreme.getUnicodeString(rawConfig, 0x32c)+":"+str(unpack("<I",rawConfig[24:28])[0]))
        dict["Domain8"] = str(xtreme.getUnicodeString(rawConfig, 0x3a6)+":"+str(unpack("<I",rawConfig[28:32])[0]))
        dict["Domain9"] = str(xtreme.getUnicodeString(rawConfig, 0x420)+":"+str(unpack("<I",rawConfig[32:36])[0]))
        dict["Domain10"] = str(xtreme.getUnicodeString(rawConfig, 0x49a)+":"+str(unpack("<I",rawConfig[36:40])[0]))
        dict["Domain11"] = str(xtreme.getUnicodeString(rawConfig, 0x514)+":"+str(unpack("<I",rawConfig[40:44])[0]))
        dict["Domain12"] = str(xtreme.getUnicodeString(rawConfig, 0x58e)+":"+str(unpack("<I",rawConfig[44:48])[0]))
        dict["Domain13"] = str(xtreme.getUnicodeString(rawConfig, 0x608)+":"+str(unpack("<I",rawConfig[48:52])[0]))
        dict["Domain14"] = str(xtreme.getUnicodeString(rawConfig, 0x682)+":"+str(unpack("<I",rawConfig[52:56])[0]))
        dict["Domain15"] = str(xtreme.getUnicodeString(rawConfig, 0x6fc)+":"+str(unpack("<I",rawConfig[56:60])[0]))
        dict["Domain16"] = str(xtreme.getUnicodeString(rawConfig, 0x776)+":"+str(unpack("<I",rawConfig[60:64])[0]))
        dict["Domain17"] = str(xtreme.getUnicodeString(rawConfig, 0x7f0)+":"+str(unpack("<I",rawConfig[64:68])[0]))
        dict["Domain18"] = str(xtreme.getUnicodeString(rawConfig, 0x86a)+":"+str(unpack("<I",rawConfig[68:72])[0]))
        dict["Domain19"] = str(xtreme.getUnicodeString(rawConfig, 0x8e4)+":"+str(unpack("<I",rawConfig[72:76])[0]))
        dict["Domain20"] = str(xtreme.getUnicodeString(rawConfig, 0x95e)+":"+str(unpack("<I",rawConfig[76:80])[0]))

        return dict

    @staticmethod
    def v32(rawConfig):
        dict = {}
        dict["ID"] = xtreme.getUnicodeString(rawConfig, 0x1b4)
        dict["Group"] = xtreme.getUnicodeString(rawConfig, 0x1ca)
        dict["Version"] = xtreme.getUnicodeString(rawConfig, 0x2bc)
        dict["Mutex"] = xtreme.getUnicodeString(rawConfig, 0x2d4)
        dict["Install Dir"] = xtreme.getUnicodeString(rawConfig, 0x1f8)
        dict["Install Name"] = xtreme.getUnicodeString(rawConfig, 0x1e2)
        dict["HKLM"] = xtreme.getUnicodeString(rawConfig, 0x23a)
        dict["HKCU"] = xtreme.getUnicodeString(rawConfig, 0x250)
        dict["ActiveX Key"] = xtreme.getUnicodeString(rawConfig, 0x266)
        dict["Injection"] = xtreme.getUnicodeString(rawConfig, 0x216)
        dict["FTP Server"] = xtreme.getUnicodeString(rawConfig, 0x35e)
        dict["FTP UserName"] = xtreme.getUnicodeString(rawConfig, 0x402)
        dict["FTP Password"] = xtreme.getUnicodeString(rawConfig, 0x454)
        dict["FTP Folder"] = xtreme.getUnicodeString(rawConfig, 0x3b0)
        dict["Domain1"] = str(xtreme.getUnicodeString(rawConfig, 0x14)+":"+str(unpack("<I",rawConfig[0:4])[0]))
        dict["Domain2"] = str(xtreme.getUnicodeString(rawConfig, 0x66)+":"+str(unpack("<I",rawConfig[4:8])[0]))
        dict["Domain3"] = str(xtreme.getUnicodeString(rawConfig, 0xb8)+":"+str(unpack("<I",rawConfig[8:12])[0]))
        dict["Domain4"] = str(xtreme.getUnicodeString(rawConfig, 0x10a)+":"+str(unpack("<I",rawConfig[12:16])[0]))
        dict["Domain5"] = str(xtreme.getUnicodeString(rawConfig, 0x15c)+":"+str(unpack("<I",rawConfig[16:20])[0]))
        dict["Msg Box Title"] = xtreme.getUnicodeString(rawConfig, 0x50c)
        dict["Msg Box Text"] = xtreme.getUnicodeString(rawConfig, 0x522)
        return dict

    @staticmethod
    def v35(rawConfig):
        dict = {}
        dict["ID"] = xtreme.getUnicodeString(rawConfig, 0x1b4)
        dict["Group"] = xtreme.getUnicodeString(rawConfig, 0x1ca)
        dict["Version"] = xtreme.getUnicodeString(rawConfig, 0x2d8)
        dict["Mutex"] = xtreme.getUnicodeString(rawConfig, 0x2f0)
        dict["Install Dir"] = xtreme.getUnicodeString(rawConfig, 0x1f8)
        dict["Install Name"] = xtreme.getUnicodeString(rawConfig, 0x1e2)
        dict["HKLM"] = xtreme.getUnicodeString(rawConfig, 0x23a)
        dict["HKCU"] = xtreme.getUnicodeString(rawConfig, 0x250)
        dict["ActiveX Key"] = xtreme.getUnicodeString(rawConfig, 0x266)
        dict["Injection"] = xtreme.getUnicodeString(rawConfig, 0x216)
        dict["FTP Server"] = xtreme.getUnicodeString(rawConfig, 0x380)
        dict["FTP UserName"] = xtreme.getUnicodeString(rawConfig, 0x422)
        dict["FTP Password"] = xtreme.getUnicodeString(rawConfig, 0x476)
        dict["FTP Folder"] = xtreme.getUnicodeString(rawConfig, 0x3d2)
        dict["Domain1"] = str(xtreme.getUnicodeString(rawConfig, 0x14)+":"+str(unpack("<I",rawConfig[0:4])[0]))
        dict["Domain2"] = str(xtreme.getUnicodeString(rawConfig, 0x66)+":"+str(unpack("<I",rawConfig[4:8])[0]))
        dict["Domain3"] = str(xtreme.getUnicodeString(rawConfig, 0xb8)+":"+str(unpack("<I",rawConfig[8:12])[0]))
        dict["Domain4"] = str(xtreme.getUnicodeString(rawConfig, 0x10a)+":"+str(unpack("<I",rawConfig[12:16])[0]))
        dict["Domain5"] = str(xtreme.getUnicodeString(rawConfig, 0x15c)+":"+str(unpack("<I",rawConfig[16:20])[0]))
        dict["Msg Box Title"] = xtreme.getUnicodeString(rawConfig, 0x52c)
        dict["Msg Box Text"] = xtreme.getUnicodeString(rawConfig, 0x542)
        return dict

    @staticmethod
    def getString(buf,pos):
        out = ""
        for c in buf[pos:]:
            if ord(c) == 0:
                break
            out += c

        if out == "":
            return None
        else:
            return out

    @staticmethod
    def getUnicodeString(buf,pos):
        out = ""
        for i in range(len(buf[pos:])):
            if not (ord(buf[pos+i]) >= 32 and ord(buf[pos+i]) <= 126) and not (ord(buf[pos+i+1]) >= 32 and ord(buf[pos+i+1]) <= 126):
                out += "\x00"
                break
            out += buf[pos+i]
        if out == "":
            return None
        else:
            return out.replace("\x00", "")

    def get_bot_information(self, file_data):
        results = {}
        uri_path = None
        domain = None
        s = xtreme.run(file_data)
        if s is not None:
            results = s

        for key in s.keys():
            s[key] = s[key].decode("ascii", errors="replace")


        c2s = set()
        for key in [i for i in results.keys() if i.startswith("Domain") and results[i] != ":0"]:
            c2s.add("tcp://" + results[key])

        if len(c2s) > 0:
            results['c2s'] = []
            for c2 in c2s:
                results['c2s'].append({"c2_uri": c2})

        return results


Modules.list.append(xtreme())