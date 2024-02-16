import os


"""

LastFileId - A class for managing the last known successfully downloaded log file

"""


class LastFileId:

    def __init__(self, config_path):
        self.config_path = config_path

    """
    Gets the last known successfully downloaded log file id
    """

    def get_last_log_id(self):
        # gets the LastKnownDownloadedFileId file
        index_file_path = os.path.join(self.config_path, "LastKnownDownloadedFileId.txt")

        # if the file exists - get the log file id from it

        if os.path.exists(index_file_path):
            with open(index_file_path, "r+") as index_file:
                return index_file.read()
        # return an empty string if no file exists
        return ''

    """
    Update the last known successfully downloaded log file id
    """

    def update_last_log_id(self, last_id):
        # gets the LastKnownDownloadedFileId file
        index_file_path = os.path.join(self.config_path, "LastKnownDownloadedFileId.txt")
        with open(index_file_path, "wt", encoding="utf-8") as index_file:
            # update the id
            index_file.write(last_id)
            index_file.close()

    """
    Remove the LastKnownDownloadedFileId.txt file. Used to skip missing files.
    """

    def remove_last_log_id(self):
        index_file_path = os.path.join(self.config_path, "LastKnownDownloadedFileId.txt")
        if os.path.exists(index_file_path):
            os.remove(index_file_path)

    """
    Gets the next log file name that we should download
    """

    def get_next_file_name(self, skip_files=0):
        # get the current stored last known successfully downloaded log file
        curr_log_file_name_arr = self.get_last_log_id().split("_")
        # get the current id
        curr_log_file_id = int(curr_log_file_name_arr[1].rstrip(".log")) + 1 + skip_files
        # build the next log file name
        new_log_file_id = curr_log_file_name_arr[0] + "_" + str(curr_log_file_id) + ".log"
        return new_log_file_id

    """
    Increment the last known successfully downloaded log file id
    """

    def move_to_next_file(self):
        self.update_last_log_id(self.get_next_file_name())