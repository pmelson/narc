from sys import path
import BAMF_Detect.modules
import BAMF_Detect.modules.common
import BAMF_Detect.preprocessors.common
import BAMF_Detect.postprocessors.common
from os.path import isfile, isdir, join, abspath, dirname, getsize
from os import write, close, remove
from pefile import PE
from glob import iglob
from zipfile import is_zipfile, ZipFile
from rarfile import is_rarfile, RarFile
import tarfile
from tempfile import mkstemp
import threading
import Queue
import time
from LimitedThreadPool import LimitedThreadPool as Pool
import traceback
import sys

path.append(dirname(abspath(__file__)))


def get_version():
    return "1.6.15"


def get_loaded_modules():
    l = []
    for m in modules.common.Modules.list:
        l.append(m.get_metadata())
    return l


def scan_file_data(file_content, module_filter, only_detect):
    """

    @param file_content:
    @param module_filter:
    @param only_detect:
    @return:
    """
    # todo php deobfuscation preprocessor
    is_pe = False
    try:
        PE(data=file_content)
        is_pe = True
    except KeyboardInterrupt:
        raise
    except:
        is_pe = False

    preprocessor_data = {}
    for preprocessor in BAMF_Detect.preprocessors.common.Preprocessors.list:
        data_to_add, file_data = preprocessor.do_processing(file_content)
        file_content = file_data
        for key in data_to_add.keys():
            preprocessor_data[key] = data_to_add[key]

    for m in modules.common.Modules.list:
        if not is_pe and m.get_datatype() == "PE":
            continue
        if module_filter is not None and m.get_module_name() not in module_filter:
            continue
        if m.is_bot(file_content):
            results = {}
            if not only_detect:
                try:
                    results["information"] = m.get_bot_information(file_content)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    results["information"] = {}
                    results["exception_details"] = {"message": e.message, "traceback": traceback.format_tb(exc_traceback)}
            results["type"] = m.get_bot_name()
            results["module"] = m.get_module_name()
            results["description"] = m.get_metadata().description
            results["preprocessor"] = preprocessor_data

            postprocessor_data = {}
            for postprocessor in BAMF_Detect.postprocessors.common.Postprocessors.list:
                data_to_add, file_data = postprocessor.do_processing(file_content, results)
                file_content = file_data
                for key in data_to_add.keys():
                    postprocessor_data[key] = data_to_add[key]
            results["postprocessor"] = postprocessor_data
            return results
    return None


def write_file_to_temp_file(file_data):
    file_handle, path = mkstemp()
    write(file_handle, file_data)
    close(file_handle)
    return path


def handle_file(file_path, module_filter, only_detect, is_temp_file=False):
    # todo modular archive handling
    # todo PE overlay extraction
    # todo PE resources extraction
    # todo Installer extraction
    if is_zipfile(file_path):
        # extract each file and handle it
        # todo consider adding archive password support
        try:
            z = ZipFile(file_path)
            for n in z.namelist():
                data = z.read(n)
                new_path = write_file_to_temp_file(data)
                for p, r in handle_file(new_path, module_filter, only_detect, is_temp_file=True):
                    result_path = ""
                    if is_temp_file:
                        result_path = n
                    else:
                        result_path = file_path + "," + n
                    if p is not None:
                        result_path += "," + p
                    yield result_path, r
                remove(new_path)
        except KeyboardInterrupt:
            raise
        except:
            pass
    elif tarfile.is_tarfile(file_path):
        try:
            with tarfile.open(file_path, 'r') as z:
                for member in z.getmembers():
                    try:
                        data = z.extractfile(member).read()
                        n = member.name
                        new_path = write_file_to_temp_file(data)
                        for p, r in handle_file(new_path, module_filter, only_detect, is_temp_file=True):
                            result_path = ""
                            if is_temp_file:
                                result_path = n
                            else:
                                result_path = file_path + "," + n
                            if p is not None:
                                result_path += "," + p
                            yield result_path, r
                        remove(new_path)
                    except KeyboardInterrupt:
                        raise
                    except:
                        pass
        except KeyboardInterrupt:
            raise
        except:
            pass
    elif is_rarfile(file_path):
        try:
            z = RarFile(file_path)
            for n in z.namelist():
                data = z.read(n)
                new_path = write_file_to_temp_file(data)
                for p, r in handle_file(new_path, module_filter, only_detect, is_temp_file=True):
                    result_path = ""
                    if is_temp_file:
                        result_path = n
                    else:
                        result_path = file_path + "," + n
                    if p is not None:
                        result_path += "," + p
                    yield result_path, r
                remove(new_path)
        except KeyboardInterrupt:
            raise
        except:
            pass
    else:
        # assume we are dealing with a normal file
        # todo Convert file handling to use file paths
        if getsize(file_path) < 1024 * 1024 * 1024:
            with open(file_path, mode='rb') as file_handle:
                file_content = file_handle.read()
                r = scan_file_data(file_content, module_filter, only_detect)
                if r is not None:
                    if is_temp_file:
                        yield None, r
                    else:
                        yield file_path, r

# async scanning variables
result_queue = Queue.Queue()
count_lock = threading.RLock()
count_queued = 0
count_finished = 0


def async_handle_file(file_path, module_filter, only_detect):
    global count_lock, count_finished, result_queue
    try:
        for fp, r in handle_file(file_path, module_filter, only_detect):
            result_queue.put((fp, r))
    finally:
        with count_lock:
            count_finished += 1


def async_scanning(paths, only_detect, recursive, module_filter, process_count=4):
    global result_queue, count_lock, count_queued, count_finished

    pool = Pool(processes=process_count)

    # loop paths
    while len(paths) != 0:
        file_path = abspath(paths[0])
        del paths[0]
        if isfile(file_path):
            with count_lock:
                count_queued += 1
            pool.apply_async(async_handle_file, [file_path, module_filter, only_detect])
        elif isdir(file_path):
            for p in iglob(join(file_path, "*")):
                p = join(file_path, p)
                if isdir(p) and recursive:
                    paths.append(p)
                if isfile(p):
                    with count_lock:
                        count_queued += 1
                    pool.apply_async(async_handle_file, [p, module_filter, only_detect])
        while True:
            try:
                r = result_queue.get_nowait()
                yield r
                result_queue.task_done()
            except Queue.Empty:
                break

    while True:
        try:
            result = result_queue.get_nowait()
            yield result
            result_queue.task_done()
        except Queue.Empty:
            with count_lock:
                if count_queued == count_finished:
                    break
            time.sleep(0.1)


def scan_paths(paths, only_detect, recursive, module_filter):
    """
    Scans paths for known bots and dumps information from them

    @rtype : dict
    @param paths: list of paths to check for files
    @param only_detect: only detect known bots, don't process configuration information
    @param recursive: recursively traverse folders
    @param module_filter: if not None, only modules in list will be used
    @return: dictionary of file to dictionary of information for each file
    """
    while len(paths) != 0:
        file_path = abspath(paths[0])
        del paths[0]
        if isfile(file_path):
            for fp, r in handle_file(file_path, module_filter, only_detect):
                yield fp, r
        elif isdir(file_path):
            for p in iglob(join(file_path, "*")):
                p = join(file_path, p)
                if isdir(p) and recursive:
                    paths.append(p)
                if isfile(p):
                    for fp, r in handle_file(p, module_filter, only_detect):
                        yield fp, r