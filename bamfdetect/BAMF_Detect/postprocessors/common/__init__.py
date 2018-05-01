

class Postprocessor:
    def __init__(self, name=None, author=None, description=None, date=None, references=None, version=None, priority=3):
        self.priority = priority
        self.name = name
        self.author = author
        self.description = description
        self.date = date
        self.references = references
        self.version = version

    def get_priority(self):
        return self.priority

    def _do_processing(self, file_data, config):
        raise

    def do_processing(self, file_data, config):
        data_to_add, updated_file_data = self._do_processing(file_data, config)
        return data_to_add, updated_file_data


class Postprocessors:
    list = []

    def __init__(self):
        pass

    @staticmethod
    def add_postprocessor(preprocessor):
        # todo Add priority sorting
        Postprocessors.list.append(preprocessor)