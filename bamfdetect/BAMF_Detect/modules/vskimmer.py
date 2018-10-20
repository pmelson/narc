from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class vskimmer(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="vskimmer",
            bot_name="vSkimmer",
            description="Point of sale malware designed to extract credit card information from RAM",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="September 2, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("vskimmer.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        uri_path = None
        domain = None
        for s in data_strings(file_data):
            if is_ip_or_domain(s):
                domain = s
            if ".php?" in s:
                uri_path = s

        if domain is not None and uri_path is not None:
            results["c2_uri"] = "{0}{1}".format(domain, uri_path)

        return results


Modules.list.append(vskimmer())