from common import Modules, data_strings, load_yara_rules, AndroidParseModule, ModuleMetadata
from base64 import b64decode
from string import printable


class dendroid(AndroidParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="dendroid",
            bot_name="Dendroid",
            description="Android RAT",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="August 18, 2014",
            references=[]
        )
        AndroidParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("dendroid.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        uri = None
        password = None
        for s in data_strings(file_data, charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx yz0123456789+/="):
            try:
                line = b64decode(s)
                if len(line) == 0:
                    continue
                valid = True
                for c in line:
                    if c not in printable:
                        valid = False
                if not valid:
                    continue
                if line.lower().startswith("https://") or line.lower().startswith("http://"):
                    uri = line
                    continue
                if uri is not None:
                    password = line
                    break
            except TypeError:
                continue
        if uri is not None:
            results["c2_uri"] = uri
            if password is not None:
                try:
                    password.decode("utf8")
                    results["password"] = password
                except UnicodeDecodeError:
                    results["password"] = "h" + password.encode("hex")
        return results


Modules.list.append(dendroid())