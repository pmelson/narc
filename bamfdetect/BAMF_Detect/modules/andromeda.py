from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class andromeda(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="andromeda",
            bot_name="Andromeda",
            description="RAT",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="August 28, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("andromeda.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        config_index = file_data.find("\x1c\x1c\x1d\x03\x49\x47\x46")
        c2_uri = ""
        for c in "thisshitismoresafethanpentagonfuckyoufedsbecausethisisaf.com/image.php":
            c2_uri += chr(ord(c) ^ ord(file_data[config_index]))
            config_index += 1
            if c2_uri.endswith(".php"):
                break
        if c2_uri.endswith(".php"):
            results["c2_uri"] = c2_uri
        return results


Modules.list.append(andromeda())