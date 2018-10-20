from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class genome(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="genome",
            bot_name="Genome",
            description="RAT",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="September 07, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("genome.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        host = None
        path = None
        for f in data_strings(file_data):
            for s in f.split("\n"):
                s = s.strip()
                if s.startswith("Host:"):
                    host = s[6:]
                if s.startswith("GET "):
                    path = s[4:][:-9]

        if host is not None and path is not None:
            results["c2_uri"] = "{0}{1}".format(host, path)
        return results


Modules.list.append(genome())