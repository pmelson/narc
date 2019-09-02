from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import pype32

class GruntStager(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="gruntstager",
            bot_name="GruntStager",
            description="RAT",
            authors=["Paul Melson (@pmelson)"],
            version="1.0.0",
            date="August 10, 2019",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("gruntstager.yara")
        return self.yara_rules

    @staticmethod
    def _is_number(s):
        if s != s.strip():
            return False
        try:
            if int(s) < 65536:
                return True
            return False
        except KeyboardInterrupt:
            raise
        except:
            return False

    @staticmethod
    def _get_strings(pe, dir_type):
        string_list = []
        m = pe.ntHeaders.optionalHeader.dataDirectory[14].info
        for s in m.netMetaDataStreams[dir_type].info:
            for offset, value in s.iteritems():
                string_list.append(value)
        return string_list


    def get_bot_information(self, file_data):
        results = {}
        pe = pype32.PE(data=file_data)
        string_list = GruntStager._get_strings(pe, 2)
        c2_url = string_list[1]
        results['c2_uri'] = c2_url
        return results


Modules.list.append(GruntStager())
