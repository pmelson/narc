from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class virusrat(PEParseModule):

    def __init__(self):
        md = ModuleMetadata(
            module_name="virusrat",
            bot_name="VirusRat",
            description="Remote access trojan",
            authors=["Paul Melson @pmelson (based on @KevTheHermit's RATdecoder)"],
            version="1.0.0",
            date="December 7, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass


    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("virusrat.yara")
        return self.yara_rules


    def get_bot_information(self, file_data):
        results = {}
        domain = None
        port = None
        config = file_data.split("abccba")
        domain = config[1]
        port = config[2]
        if domain is not None and port is not None:
            results['c2_uri'] = "tcp://{0}:{1}".format(domain, port)
        return results


Modules.list.append(virusrat())
