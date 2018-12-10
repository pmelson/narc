from common import Modules, load_yara_rules, PEParseModule, ModuleMetadata
from pefile import PE, RESOURCE_TYPE
from string import printable


class CyberGate(PEParseModule):
    first_value_table = None
    precomputed_list = None

    def __init__(self):
        md = ModuleMetadata(
            module_name="cybergate",
            bot_name="CyberGate",
            description="RAT",
            authors=["Kevin Breen <kevin@techanarchy.net>", "Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="Aug 30, 2015",
            references=[
                "https://github.com/kevthehermit/YaraRules/blob/master/CyberGate.yar",
                "https://github.com/kevthehermit/RATDecoders/blob/master/CyberGate.py"
            ]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        self.prng_seed = 0

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("cybergate.yara")
        return self.yara_rules

    @staticmethod
    def xor_decode(data):
        key = 0xBC
        encoded = bytearray(data)
        for i in range(len(encoded)):
            encoded[i] ^= key
        return filter(lambda x: x in printable, str(encoded))

    @staticmethod
    def config_extract(raw_data):
        try:
            pe = PE(data=raw_data)

            try:
                rt_string_idx = [
                    entry.id for entry in
                    pe.DIRECTORY_ENTRY_RESOURCE.entries].index(RESOURCE_TYPE['RT_RCDATA'])
            except ValueError:
                return None
            except AttributeError:
                return None

            rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

            for entry in rt_string_directory.directory.entries:
                if str(entry.name) == "XX-XX-XX-XX" or str(entry.name) == "CG-CG-CG-CG":
                    data_rva = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
                    data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                    config = data.split('####@####')
                    return config
        except:
            return None

    @staticmethod
    def run_config_extraction(data):
        Config = {}
        rawConfig = CyberGate.config_extract(data)
        if rawConfig != None:
            if len(rawConfig) > 20:
                domains = ""
                ports = ""
                #Config sections 0 - 19 contain a list of Domains and Ports
                for x in range(0,19):
                    if len(rawConfig[x]) > 1:
                        domains += CyberGate.xor_decode(rawConfig[x]).split(':')[0]
                        domains += "|"
                        ports += CyberGate.xor_decode(rawConfig[x]).split(':')[1]
                        ports += "|"
                Config["Domain"] = domains
                Config["Port"] = ports
                Config["ServerID"] = CyberGate.xor_decode(rawConfig[20])
                Config["Password"] = CyberGate.xor_decode(rawConfig[21])
                Config["Install Flag"] = CyberGate.xor_decode(rawConfig[22])
                Config["Install Directory"] = CyberGate.xor_decode(rawConfig[25])
                Config["Install File Name"] = CyberGate.xor_decode(rawConfig[26])
                Config["Active X Startup"] = CyberGate.xor_decode(rawConfig[27])
                Config["REG Key HKLM"] = CyberGate.xor_decode(rawConfig[28])
                Config["REG Key HKCU"] = CyberGate.xor_decode(rawConfig[29])
                Config["Enable Message Box"] = CyberGate.xor_decode(rawConfig[30])
                Config["Message Box Icon"] = CyberGate.xor_decode(rawConfig[31])
                Config["Message Box Button"] = CyberGate.xor_decode(rawConfig[32])
                Config["Install Message Title"] = CyberGate.xor_decode(rawConfig[33])
                Config["Install Message Box"] = CyberGate.xor_decode(rawConfig[34]).replace('\r\n', ' ')
                Config["Activate Keylogger"] = CyberGate.xor_decode(rawConfig[35])
                Config["Keylogger Backspace = Delete"] = CyberGate.xor_decode(rawConfig[36])
                Config["Keylogger Enable FTP"] = CyberGate.xor_decode(rawConfig[37])
                Config["FTP Address"] = CyberGate.xor_decode(rawConfig[38])
                Config["FTP Directory"] = CyberGate.xor_decode(rawConfig[39])
                Config["FTP UserName"] = CyberGate.xor_decode(rawConfig[41])
                Config["FTP Password"] = CyberGate.xor_decode(rawConfig[42])
                Config["FTP Port"] = CyberGate.xor_decode(rawConfig[43])
                Config["FTP Interval"] = CyberGate.xor_decode(rawConfig[44])
                Config["Persistance"] = CyberGate.xor_decode(rawConfig[59])
                Config["Hide File"] = CyberGate.xor_decode(rawConfig[60])
                Config["Change Creation Date"] = CyberGate.xor_decode(rawConfig[61])
                Config["Mutex"] = CyberGate.xor_decode(rawConfig[62])
                Config["Melt File"] = CyberGate.xor_decode(rawConfig[63])
                Config["CyberGate Version"] = CyberGate.xor_decode(rawConfig[67])
                Config["Startup Policies"] = CyberGate.xor_decode(rawConfig[69])
                Config["USB Spread"] = CyberGate.xor_decode(rawConfig[70])
                Config["P2P Spread"] = CyberGate.xor_decode(rawConfig[71])
                Config["Google Chrome Passwords"] = CyberGate.xor_decode(rawConfig[73])
                Config["Process Injection"] = "Disabled"
                if CyberGate.xor_decode(rawConfig[57]) == 0 or CyberGate.xor_decode(rawConfig[57]) == None:
                    Config["Process Injection"] = "Disabled"
                elif CyberGate.xor_decode(rawConfig[57]) == 1:
                    Config["Process Injection"] = "Default Browser"
                elif CyberGate.xor_decode(rawConfig[57]) == 2:
                    Config["Process Injection"] = CyberGate.xor_decode(rawConfig[58])
            else:
                return None
            return Config

    def get_bot_information(self, file_data):
        results = CyberGate.run_config_extraction(file_data)
        if results is None:
            results = {}
        elif "Domain" in results and "Port" in results:
            domains = results["Domain"].split("|")
            ports = results["Port"].split("|")
            c2s = []

            for i in xrange(len(domains)):
                if len(domains[i].strip()) == 0 or len(ports[i].strip()) == 0:
                    continue
                c2s.append({"c2_uri": "tcp://{0}:{1}/".format(domains[i], ports[i])})

            results["c2s"] = c2s
            pass

        return results


Modules.list.append(CyberGate())