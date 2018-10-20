from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata
import json


class BlackShades(PEParseModule):
    first_value_table = None
    precomputed_list = None

    def __init__(self):
        md = ModuleMetadata(
            module_name="blackshades",
            bot_name="BlackShades",
            description="RAT developed in Visual Basic 6",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="August 16, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        self.prng_seed = 0

    def is_valid_config(self, config):
        if config[:3] != "\x0c\x0c\x0c":
            return False
        if config.count("\x0C\x0C\x0C") < 15:
            return False
        return True

    def get_next_rng_value(self):
        self.prng_seed = ((self.prng_seed * 1140671485 + 12820163) & 0xffffff)
        return self.prng_seed >> 16

    def decrypt_configuration(self, hex):
        if self.precomputed_list is None:
            self.precomputed_list = [((a * 1140671485 + 12820163) & 0xffffff) >> 16 for a in xrange(0xffffff)]
        if self.first_value_table is None:
            self.first_value_table = {}

        ascii = hex.decode('hex')
        tail = ascii[0x20:]

        pre_check = []
        for x in xrange(3):
            pre_check.append(ord(tail[x]) ^ 0x0c)

        if pre_check[0] not in self.first_value_table:
            t = pre_check[0]
            self.first_value_table[t] = [a for a in xrange(len(self.precomputed_list)) if self.precomputed_list[a] == t]
        possible_values = self.first_value_table[pre_check[0]]

        for x in possible_values:
            self.prng_seed = x
            if self.get_next_rng_value() != pre_check[0] or self.get_next_rng_value() != pre_check[1] or \
                self.get_next_rng_value() != pre_check[2]:
                continue
            self.prng_seed = x
            config = "".join((chr(ord(c) ^ int(self.get_next_rng_value())) for c in tail))
            if "\x0C\x0C\x0C" in config and self.is_valid_config(config):
                return config.split("\x0c\x0c\x0c")
        return None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("blackshades.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        for s in data_strings(file_data, 154, "0123456789abcdefABCDEF"):
            if (len(s) % 2) == 1:
                s = s[:-1]
            ret = self.decrypt_configuration(s)
            if ret is not None and len(ret) > 15:
                results["ip"] = ret[1]
                results["control_port"] = ret[2]
                results["transfer_port"] = ret[3]
                try:
                    ret[4].decode("utf-8")
                    results["bot_name"] = ret[4]
                except UnicodeDecodeError:
                    results["bot_name"] = "h" + ret[4].encode("hex")
                results["file_name"] = ret[5]
                results["install_folder"] = ret[6]
                results["registry_persistence"] = ret[7]
                results["active_setup_persistence_name"] = ret[8]
                results["mutex_name"] = ret[14]
                results["c2_uri"] = "{0}:{1}".format(results["ip"], results["control_port"])
        return results


Modules.list.append(BlackShades())