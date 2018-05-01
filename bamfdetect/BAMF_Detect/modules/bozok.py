from common import Modules, load_yara_rules, PEParseModule, ModuleMetadata
from pefile import PE, RESOURCE_TYPE


class Bozok(PEParseModule):
    first_value_table = None
    precomputed_list = None

    def __init__(self):
        md = ModuleMetadata(
            module_name="bozok",
            bot_name="Bozok",
            description="RAT",
            authors=["Kevin Breen <kevin@techanarchy.net>", "Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="Aug 30, 2015",
            references=[
                "https://github.com/kevthehermit/YaraRules/blob/master/Bozok.yar",
                "https://github.com/kevthehermit/RATDecoders/blob/master/Bozok.py"
            ]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        self.prng_seed = 0

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("bozok.yara")
        return self.yara_rules

    @staticmethod
    def configExtract(rawData):
        pe = PE(data=rawData)

        try:
            rt_string_idx = [
                entry.id for entry in
                pe.DIRECTORY_ENTRY_RESOURCE.entries].index(RESOURCE_TYPE['RT_RCDATA'])
        except ValueError, e:
            return None
        except AttributeError, e:
            return None

        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "CFG":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                return data

    @staticmethod
    def run_config_extraction(data):
        conf = {}
        c = Bozok.configExtract(data)
        if c is None:
            return None
        rawConfig = c.replace('\x00', '')
        config = rawConfig.split("|")
        if config is not None:
            conf["ServerID"] = config[0]
            conf["Mutex"] = config[1]
            conf["InstallName"] = config[2]
            conf["StartupName"] = config[3]
            conf["Extension"] = config[4]
            conf["Password"] = config[5]
            conf["Install Flag"] = config[6]
            conf["Startup Flag"] = config[7]
            conf["Visible Flag"] = config[8]
            conf["Unknown Flag1"] = config[9]
            conf["Unknown Flag2"] = config[10]
            conf["Port"] = config[11]
            conf["Domain"] = config[12]
            conf["Unknown Flag3"] = config[13]
        return conf

    def get_bot_information(self, file_data):
        results = Bozok.run_config_extraction(file_data)

        if results is None:
            return {}

        for key in results.keys():
            results[key] = results[key].encode("string-escape")

        if "Domain" in results and "Port" in results:
            domains = results['Domain'].split("*")
            c2s = []
            for d in [i for i in domains if len(i.strip()) > 0]:
                c2s.append({"c2_uri": "tcp://{0}:{1}/".format(d, results["Port"])})
            results["c2s"] = c2s

        return results


Modules.list.append(Bozok())