from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class easterjackpos(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="easterjackpos",
            bot_name="Easter JackPOS",
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
            self.yara_rules = load_yara_rules("easterjackpos.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        uri_paths = None
        domains = None
        for s in data_strings(file_data):
            if is_ip_or_domain(s):
                if domains is None:
                    domains = set()
                domains.add(s)
            if s.endswith(".php"):
                if uri_paths is None:
                    uri_paths = set()
                uri_paths.add(s)

        if domains is not None and uri_paths is not None:
            results["c2s"] = []
            for d in domains:
                for p in uri_paths:
                    results["c2s"].append({"c2_uri": "{0}{1}".format(d, p)})

        return results


Modules.list.append(easterjackpos())