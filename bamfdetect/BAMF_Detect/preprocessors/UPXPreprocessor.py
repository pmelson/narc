from BAMF_Detect.preprocessors.common import Preprocessor, Preprocessors
from pefile import PE
from tempfile import mkstemp
from os import write, close, remove
from subprocess import Popen, PIPE


def is_upx_compressed(data):
    pe = PE(data=data)
    for entry in pe.sections:
        if entry.Name.startswith("UPX0") or entry.Name.startswith("UPX1"):
            return True
    return False


def decompress_upx(file_data):
    file_handle, path = mkstemp()
    write(file_handle, file_data)
    close(file_handle)
    p = Popen(['upx', '-d', path], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    with open(path, "rb") as f:
        file_data = f.read()
    remove(path)
    return file_data


class UPXPreprocessor(Preprocessor):
    def __init__(self):
        Preprocessor.__init__(
            self,
            name="UPX",
            author="Brian Wallace (@botnet_hunter)",
            date="December 24th, 2014",
            description="Decompressed UPX packed binaries",
            references="",
            version="1.0.0.0"
        )

    def _do_processing(self, file_data):
        # todo Don't run if upx cli tool is not available
        # todo UPX is temporarily disabled
        try:
            if is_upx_compressed(file_data):
                decompressed = decompress_upx(file_data)
                data_to_add = {"upx_compressed": True}
                return data_to_add, decompressed
        except KeyboardInterrupt:
            raise
        except:
            return {"upx_compressed": False}, file_data
        return {"upx_compressed": False}, file_data

Preprocessors.add_preprocessor(UPXPreprocessor())
