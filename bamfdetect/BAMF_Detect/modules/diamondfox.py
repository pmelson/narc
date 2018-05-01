from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import pefile


class diamondfox(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="diamondfox",
            bot_name="diamondfox",
            description="Bot that steals passwords, DDoSes, etc, written in VB6",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.1.0",
            date="August 22, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("diamondfox.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}

        pe = pefile.PE(data=file_data)
        custom_resource = [i for i in pe.DIRECTORY_ENTRY_RESOURCE.entries if str(i.name) == 'CUSTOM']

        if len(custom_resource) == 0:
            # We need to also check the end of the file
            if "<--------->" in file_data:
                spl = file_data.split("<--------->")
                if len(spl) > 1:
                    config_raw = spl[1]
                    resource_key = ord(config_raw[0]) ^ ord("<")
                    config = "".join([chr(ord(i) ^ resource_key) for i in config_raw])
                    config = config.replace("<Configs>", "").replace("</Configs>", "").strip()
                    keys_to_decrypt = ["Panel", "FBP", "UsA"]
                    config_dict = {}

                    while len(config) > 0:
                        key = config[:config.find(">") + 1]
                        config = config[config.find(">") + 1:]
                        data = config[:config.find(key.replace("<", "</"))]
                        config = config[config.find(key.replace("<", "</")) + len(key) + 1:].strip()
                        config_dict[key.replace("<", "").replace(">", "")] = data


                    xor = ord(config_dict["Xor"][0])
                    for k in keys_to_decrypt:
                        if k not in config_dict:
                            continue
                        data = config_dict[k]
                        config_dict[k] = "".join([chr(xor ^ ord(data[i])) for i in xrange(len(data))])
                        config_dict[k] = "".join([chr(xor ^ ord(i)) for i in data])

                    results["raw_config"] = config_dict
                    c2_keys = ["Panel", "FBP"]
                    if len([i for i in c2_keys if i in config_dict]) > 0:
                        if "c2s" not in results:
                            results["c2s"] = []
                        for i in [config_dict[i] for i in c2_keys if i in config_dict and len(config_dict[i]) > 0]:
                            results["c2s"].append({"c2_uri": i})

            return results

        custom_resource = custom_resource[0]

        for entry in custom_resource.directory.entries:
            if entry.name.string == "101":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                config_raw = pe.get_data(data_rva, size)

                resource_key = ord(config_raw[0]) ^ ord("<")
                config = "".join([chr(ord(i) ^ resource_key) for i in config_raw])
                config = config.replace("<Configs>", "").replace("</Configs>", "").strip()
                keys_to_decrypt = ["Panel", "FBP", "UsA"]
                config_dict = {}

                while len(config) > 0:
                    key = config[:config.find(">") + 1]
                    config = config[config.find(">") + 1:]
                    data = config[:config.find(key.replace("<", "</"))]
                    config = config[config.find(key.replace("<", "</")) + len(key) + 1:].strip()
                    config_dict[key.replace("<", "").replace(">", "")] = data


                xor = ord(config_dict["Xor"][0])
                for k in keys_to_decrypt:
                    if k not in config_dict:
                        continue
                    data = config_dict[k]
                    config_dict[k] = "".join([chr(xor ^ ord(data[i])) for i in xrange(len(data))])
                    config_dict[k] = "".join([chr(xor ^ ord(i)) for i in data])

                results["raw_config"] = config_dict
                c2_keys = ["Panel", "FBP"]
                if len([i for i in c2_keys if i in config_dict]) > 0:
                    if "c2s" not in results:
                        results["c2s"] = []
                    for i in [config_dict[i] for i in c2_keys if i in config_dict and len(config_dict[i]) > 0]:
                        results["c2s"].append({"c2_uri": i})

        return results


Modules.list.append(diamondfox())