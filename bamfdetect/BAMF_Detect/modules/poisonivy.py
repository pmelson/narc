from common import Modules, load_yara_rules, PEParseModule, ModuleMetadata
from string import printable
from struct import unpack


class PoisonIvy(PEParseModule):
    first_value_table = None
    precomputed_list = None

    def __init__(self):
        md = ModuleMetadata(
            module_name="poisonivy",
            bot_name="PoisonIvy",
            description="RAT",
            authors=["Kevin Breen <kevin@techanarchy.net>", "Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="Aug 30, 2015",
            references=[
                "https://github.com/kevthehermit/YaraRules/blob/master/PoisonIvy.yar",
                "https://github.com/kevthehermit/RATDecoders/blob/master/PoisonIvy.py"
            ]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        self.prng_seed = 0

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("poisonivy.yara")
        return self.yara_rules

    @staticmethod
    def run_config_extraction(data):
        # Split to get start of Config
        one = PoisonIvy.firstSplit(data)
        if one is None:
            return None
        # If the split works try to walk the strings
        two = PoisonIvy.dataWalk(one)
        # lets Process this and format the config
        three = PoisonIvy.configProcess(two)
        return three

    @staticmethod
    def calcLength(byteStr):
        try:
            return unpack("<H", byteStr)[0]
        except:
            return None

    @staticmethod
    def stringPrintable(line):
        return filter(lambda x: x in printable, line)

    @staticmethod
    def firstSplit(data):
        splits = data.split('Software\\Microsoft\\Active Setup\\Installed Components\\')
        if len(splits) == 2:
            return splits[1]
        else:
            return None

    @staticmethod
    def bytetohex(byteStr):
        return ''.join(["%02X" % ord(x) for x in byteStr]).strip()

    @staticmethod
    def dataWalk(splitdata):
        # Byte array to make things easier
        stream = bytearray(splitdata)
        # End of file for our while loop
        EOF = len(stream)
        # offset to track position
        offset = 0
        this = []
        maxCount = 0
        while offset < EOF and maxCount < 22:
            try:
                length = PoisonIvy.calcLength(str(stream[offset + 2:offset + 4]))
                temp = []
                for i in range(offset + 4, offset + 4 + length):
                    temp.append(chr(stream[i]))
                dataType = PoisonIvy.bytetohex(splitdata[offset] + splitdata[offset + 1])
                this.append((dataType, ''.join(temp)))
                offset += length + 4
                maxCount += 1
            except:
                return this
        return this

    @staticmethod
    def domainWalk(rawStream):
        domains = ''
        offset = 0
        stream = bytearray(rawStream)
        while offset < len(stream):
            length = stream[offset]
            temp = []
            for i in range(offset + 1, offset + 1 + length):
                temp.append(chr(stream[i]))
            domain = ''.join(temp)

            rawPort = rawStream[offset + length + 2:offset + length + 4]
            port = PoisonIvy.calcLength(rawPort)
            offset += length + 4
            domains += "{0}:{1}|".format(domain, port)
        return domains

    @staticmethod
    def configProcess(rawConfig):
        configDict = {"Campaign ID": "", "Group ID": "", "Domains": "", "Password": "", "Enable HKLM": "",
                      "HKLM Value": "", "Enable ActiveX": "", "ActiveX Key": "", "Flag 3": "", "Inject Exe": "",
                      "Mutex": "", "Hijack Proxy": "", "Persistent Proxy": "", "Install Name": "", "Install Path": "",
                      "Copy to ADS": "", "Melt": "", "Enable Thread Persistence": "", "Inject Default Browser": "",
                      "Enable KeyLogger": ""}
        for x in rawConfig:
            if x[0] == 'FA0A':
                configDict["Campaign ID"] = PoisonIvy.stringPrintable(x[1])
            if x[0] == 'F90B':
                configDict["Group ID"] = PoisonIvy.stringPrintable(x[1])
            if x[0] == '9001':
                configDict["Domains"] = PoisonIvy.domainWalk(x[1])
            if x[0] == '4501':
                configDict["Password"] = PoisonIvy.stringPrintable(x[1])
            if x[0] == '090D':
                configDict["Enable HKLM"] = PoisonIvy.bytetohex(x[1])
            if x[0] == '120E':
                configDict["HKLM Value"] = PoisonIvy.stringPrintable(x[1])
            if x[0] == 'F603':
                configDict["Enable ActiveX"] = PoisonIvy.bytetohex(x[1])
            if x[0] == '6501':
                configDict["ActiveX Key"] = PoisonIvy.stringPrintable(x[1])
            if x[0] == '4101':
                configDict["Flag 3"] = PoisonIvy.bytetohex(x[1])
            if x[0] == '4204':
                configDict["Inject Exe"] = PoisonIvy.stringPrintable(x[1])
            if x[0] == 'Fb03':
                configDict["Mutex"] = PoisonIvy.stringPrintable(x[1])
            if x[0] == 'F40A':
                configDict["Hijack Proxy"] = PoisonIvy.bytetohex(x[1])
            if x[0] == 'F50A':
                configDict["Persistent Proxy"] = PoisonIvy.bytetohex(x[1])
            if x[0] == '2D01':
                configDict["Install Name"] = PoisonIvy.stringPrintable(x[1])
            if x[0] == 'F703':
                configDict["Install Path"] = PoisonIvy.stringPrintable(x[1])
            if x[0] == '120D':
                configDict["Copy to ADS"] = PoisonIvy.bytetohex(x[1])
            if x[0] == 'F803':
                configDict["Melt"] = PoisonIvy.bytetohex(x[1])
            if x[0] == 'F903':
                configDict["Enable Thread Persistence"] = PoisonIvy.bytetohex(x[1])
            if x[0] == '080D':
                configDict["Inject Default Browser"] = PoisonIvy.bytetohex(x[1])
            if x[0] == 'FA03':
                configDict["Enable KeyLogger"] = PoisonIvy.bytetohex(x[1])
        return configDict

    def get_bot_information(self, file_data):
        results = PoisonIvy.run_config_extraction(file_data)

        if results is None:
            return {}

        results["Domains"] = results["Domains"].replace("\x00", "").encode("string-escape")

        c2s = []
        for i in set([x for x in results["Domains"].split("|") if len(x.strip()) > 0]):
            c2s.append({"c2_uri": "tcp://{0}/".format(i)})
        results['c2s'] = c2s

        return results


Modules.list.append(PoisonIvy())