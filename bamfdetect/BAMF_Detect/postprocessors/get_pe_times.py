from BAMF_Detect.postprocessors.common import Postprocessor, Postprocessors
import pefile
import datetime


class GetPETimes(Postprocessor):
    def __init__(self):
        Postprocessor.__init__(
            self,
            name="GetPETimes",
            author="Brian Wallace (@botnet_hunter)",
            date="March 14th, 2015",
            description="Extracts the timestamps from PEs",
            references="",
            version="1.0.0.0"
        )

    @staticmethod
    def epoch_to_string(epoch):
        return datetime.datetime.fromtimestamp(epoch).strftime("%x %X")

    def _do_processing(self, file_data, results):
        to_return = {}
        try:
            times = []
            pe = pefile.PE(data=file_data)
            pe.FILE_HEADER.dump_dict()

            # I know they parse the time out into a nice string for us, but I want uniform printing...
            epoch = int(pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split(" ")[0], 16)

            times.append({"name": "FILE_HEADER", "integer": epoch, "s": GetPETimes.epoch_to_string(epoch)})
            to_return = {'times': times}

            # usually null timestamps
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    times.append({
                        "name": "DIRECTORY_ENTRY_RESOURCE",
                        "integer": entry.directory.struct.TimeDateStamp,
                        "s": GetPETimes.epoch_to_string(entry.directory.struct.TimeDateStamp)})
                except KeyboardInterrupt:
                    raise
                except:
                    pass

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    times.append({
                        "name": "DIRECTORY_ENTRY_IMPORT",
                        "integer": entry.struct.TimeDateStamp,
                        "s": GetPETimes.epoch_to_string(entry.struct.TimeDateStamp)})
                except KeyboardInterrupt:
                    raise
                except:
                    pass
            # pe.DIRECTORY_ENTRY_RESOURCE.entries[0].directory.struct.TimeDateStamp
            # pe.DIRECTORY_ENTRY_IMPORT[0].struct.TimeDateStamp

            to_return = {'times': times}
        except:
            pass

        return to_return, file_data

Postprocessors.add_postprocessor(GetPETimes())