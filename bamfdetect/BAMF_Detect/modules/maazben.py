from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain, RC4
from string import ascii_uppercase, ascii_lowercase, digits, punctuation
from pefile import PE


class maazben(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="maazben",
            bot_name="Maazben",
            description="Spam botnet",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="August 25, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("maazben.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        encrypted_section = file_data.rfind("\x44\x6d\x47\x00")
        if encrypted_section == -1:
            pe = PE(data=file_data)
            for x in xrange(len(pe.sections)):
                for s in data_strings(pe.get_data(pe.sections[x].VirtualAddress), 8, charset=ascii_uppercase + ascii_lowercase + digits + punctuation):
                    if s.startswith("http://") and s != "http://":
                        if "c2s" not in results:
                            results["c2s"] = []
                        results["c2s"].append({"c2_uri": s})
        else:
            encrypted_section += 4
            encryption_key = None
            pe = PE(data=file_data)
            for s in data_strings(pe.get_data(pe.sections[3].VirtualAddress), 7):
                # the last string
                encryption_key = s

            if encryption_key is not None:
                rc4 = RC4(encryption_key)
                decrypted = "".join([chr(rc4.next() ^ ord(c)) for c in file_data[encrypted_section:]])
                for s in data_strings(decrypted, 8, charset=ascii_uppercase + ascii_lowercase + digits + punctuation):
                    if s.startswith("http://") and s != "http://":
                        if "c2s" not in results:
                            results["c2s"] = []
                        results["c2s"].append({"c2_uri": s})

        return results


Modules.list.append(maazben())