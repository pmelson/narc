from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import base64
import hashlib
import re
from Crypto.Cipher import AES


class Plasma(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="plasma",
            bot_name="Plasma",
            description="RAT",
            authors=["Paul Melson @pmelson (based on @KevTheHermit's RATdecoder)"],
            version="1.0.0",
            date="December 10, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("plasma.yara")
        return self.yara_rules

    @staticmethod
    def _getconfig(data):
        try:
            conf_string = re.findall('[a-zA-Z0-9+/]{60,}={0,2}', data)[0]
            key_string = 'IUWEEQWIOER$89^*(&@^$*&#@$HAFKJHDAKJSFHjd89379327AJHFD*&#($hajklshdf##*$&^(AAA'
            key_hash = hashlib.md5(key_string).hexdigest()
            aes_key = key_hash[:30]+key_hash+'00'
            cipher = AES.new(aes_key.decode('hex'))
            decrypted_config = cipher.decrypt(base64.b64decode(conf_string))
            config = decrypted_config.split('*')
        except:
            config = []
        return config


    def get_bot_information(self, file_data):
        results = {}
        results['c2s'] = []
        config = []
        config = Plasma._getconfig(file_data)
        domain = config[1]
        port = config[2]
        backupdomain = config[7]
        results['c2s'].append({"c2_uri": "tcp://{0}:{1}".format(domain, port)})
        if backupdomain is not None:
            results['c2s'].append({"c2_uri": "tcp://{0}:{1}".format(backupdomain, port)})

        return results


Modules.list.append(Plasma())
