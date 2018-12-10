from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
from re import match


class herpes(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="herpes",
            bot_name="Herpes Net",
            description="Botnet that really makes your crotch itch",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="April 14, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("herpes.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        gate = None
        server = None
        for s in data_strings(file_data):
            if s.find("run.php") != -1:
                gate = s
            if s.startswith("http://") and len(s) > len("http://"):
                domain = s[7:]
                if domain.find('/') != -1:
                    domain = domain[:domain.find('/')]
                if is_ip_or_domain(domain):
                    server = s
            if match(r'^\d\.\d\.\d$', s) is not None:
                        results["version"] = s
        if server is not None and gate is not None:
            results["c2_uri"] = "%s%s" % (server, gate)
        return results


Modules.list.append(herpes())