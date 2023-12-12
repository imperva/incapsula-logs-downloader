import re
import os

"""

LogsFileIndex - A class for managing the logs files index file

"""


class LogsFileIndex:

    def __init__(self, config, logger, downloader, config_path):
        self.config_path = config_path
        self.config = config
        self.content = None
        self.hash_content = None
        self.logger = logger
        self.file_downloader = downloader

    """
    Gets the indexed log files
    """

    def indexed_logs(self) -> list:
        return self.content

    """
    Downloads a logs file index file
    """

    def download(self):
        self.logger.info("Downloading logs index file...")
        # try to get the logs.index file
        file_content = self.file_downloader.request_file_content(self.config.BASE_URL + "logs.index")
        # if we got the file content
        if file_content != "":
            content = file_content.decode("utf-8")
            # validate the file format
            if LogsFileIndex.validate_log_file_format(content):
                self.content = content.splitlines()
                self.hash_content = set(self.content)
                with open(os.path.join(self.config_path, "logs.index"), "wb") as fp:
                    fp.write(file_content)
            else:
                self.logger.error("log.index, Pattern Validation Failed")
                raise Exception
        else:
            raise Exception('Index file does not yet exist, please allow time for files to be generated.')

    """
    Validates that format name of the logs files inside the logs index file
    """

    @staticmethod
    def validate_logs_index_file_format(content):
        file_rex = re.compile("(\d+_\d+\.log\n)+")
        if file_rex.match(content):
            return True
        return False

    """
    Validates a log file name format
    """

    @staticmethod
    def validate_log_file_format(content):
        file_rex = re.compile("(\d+_\d+\.log)")
        if file_rex.match(content):
            return True
        return False