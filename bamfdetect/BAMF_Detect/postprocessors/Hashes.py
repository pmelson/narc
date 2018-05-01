from BAMF_Detect.postprocessors.common import Postprocessor, Postprocessors
import hashlib


class HashingPreprocessor(Postprocessor):
    def __init__(self):
        Postprocessor.__init__(
            self,
            name="Hashes",
            author="Brian Wallace (@botnet_hunter)",
            date="March 14th, 2015",
            description="Computes hashes for each file",
            references="",
            version="1.0.0.0"
        )

    def _do_processing(self, file_data, results):
        to_return = {}
        to_return["sha256"] = hashlib.sha256(file_data).hexdigest()
        to_return["sha1"] = hashlib.sha1(file_data).hexdigest()
        to_return["md5"] = hashlib.md5(file_data).hexdigest()

        return to_return, file_data

Postprocessors.add_postprocessor(HashingPreprocessor())