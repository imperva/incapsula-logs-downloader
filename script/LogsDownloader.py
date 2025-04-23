#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:       Doron Lehmann, Incapsula, Inc.
# Date:         2015
# Description:  Logs Downloader Client
#
# ************************************************************************************
# Copyright (c) 2015, Incapsula, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# ************************************************************************************
#

import base64
import datetime
import getopt
import hashlib
from logging import handlers
import os
import signal
import sys
import threading
import time
import traceback
import zlib
import logging
from Config import Config
from FileDownloader import FileDownloader
from HandlingLogs import HandlingLogs
from LastFileId import LastFileId
from LogsFileIndex import LogsFileIndex
from multiprocessing.pool import ThreadPool
from threading import active_count

"""
Main class for downloading log files
"""


class LogsDownloader:
    # the LogsDownloader will run until external termination
    RUNNING = True
    _start_total = None
    pool = ThreadPool()
    downloaded = []

    def __init__(self, config_path, system_log_path, log_level):
        # set a log file for the downloader
        self.logger = logging.getLogger("logsDownloader")
        # default log directory for the downloader
        log_dir = system_log_path
        # create the log directory if needed
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Set logging level
        if log_level == "DEBUG":
            self.logger.setLevel(logging.DEBUG)
        elif log_level == "INFO":
            self.logger.setLevel(logging.INFO)
        elif log_level == "ERROR":
            self.logger.setLevel(logging.ERROR)

        logging.basicConfig(
            level=log_level,
            # keep logs history for 7 days
            handlers=[logging.handlers.TimedRotatingFileHandler(os.path.join(log_dir, "logs_downloader.log"),
                                                                when='midnight', backupCount=7),
                      logging.StreamHandler(sys.stdout)],
            format="%(asctime)s %(threadName)s %(levelname)s %(message)s"
        )

        self.logger.debug("Initializing LogsDownloader")
        self.config_path = config_path
        self.config_reader = Config(self.config_path, self.logger)
        try:
            # read the configuration file and load it
            self.config = self.config_reader.read()
        except Exception:
            self.logger.error(
                "Exception while getting LogsDownloader config file - Could Not find Configuration file - %s",
                traceback.format_exc())
            sys.exit("Could Not find Configuration file")
        # Create the needed directories for handling the logs incoming, process, archive
        if not os.path.exists(self.config.INCOMING_DIR):
            os.makedirs(self.config.INCOMING_DIR)
        else:
            for file in os.listdir(self.config.INCOMING_DIR):
                os.remove(os.path.join(self.config.INCOMING_DIR, file))
        if not os.path.exists(self.config.PROCESS_DIR):
            os.makedirs(self.config.PROCESS_DIR)
        if not os.path.exists(self.config.ARCHIVE_DIR):
            os.makedirs(self.config.ARCHIVE_DIR)
        # create a file downloader handler
        self.file_downloader = FileDownloader(self.config, self.logger)
        # create a last file id handler
        self.last_known_downloaded_file_id = LastFileId(self.config_path)
        # create a logs file index handler
        self.logs_file_index = LogsFileIndex(self.config, self.logger, self.file_downloader, self.config_path)
        # Configure the remote logger, whether it be SYSLOG or Splunk HEC
        if self.config.SYSLOG_ENABLE == 'YES' or self.config.SPLUNK_HEC == 'YES':
            self.file_watcher = HandlingLogs(self.config, self.logger)
            self.file_watcher_thread = threading.Thread(target=self.file_watcher.watch_files, name="file_watcher_thread")
            self.file_watcher_thread.start()
        self.logger.info("LogsDownloader initializing is done")


    """
    Download the log files.
    If this is the first time, we get the logs.index file, scan it, and download all of the files in it.
    It this is not the first time, we try to fetch the next log file.
    """

    def get_index_file(self):
        while self.RUNNING:
            try:
                # download the logs.index file
                self.logs_file_index.download()
                # Start a timer and start processing the index
                self._start_total = time.perf_counter()
                self.start_log_processing()
            except Exception as e:
                self.logger.error(
                    "Failed to downloading index file and starting to download all the log files in it - %s, %s", e,
                    traceback.format_exc())
                # wait for 5 seconds between each iteration
                self.logger.info("Sleeping for 5 seconds before trying to fetch logs again...")
                time.sleep(5)
        self.logger.info("Exiting get_index_file.")

    """
    Scan the logs.index file, and download all the log files in it
    """

    def start_log_processing(self):
        # Get the list of file names from the index file and compare with the current processed index list
        logs_in_index = self.logs_file_index.indexed_logs()
        self.downloaded = self.get_indexed()
        additions = [x for x in logs_in_index if x not in self.downloaded]
        deletion = [x for x in self.downloaded if x not in logs_in_index]
        completed = [x for x in logs_in_index if x not in deletion]

        if len(deletion) > 0:
            self.logger.info("Clean up the passed/purged indexes.")
            self.update_complete_file(completed)
            self.logger.info("Pre and post index length: {} - {}".format(len(self.downloaded), len(self.get_indexed())))

        if len(additions) == 0:
            self.logger.info("{} new logs to download.".format(len(additions)))
            time.sleep(3)
            return

        # for each file
        self.logger.info("{} new logs to download.".format(len(additions)))

        for log_file_name in additions:
            if not self.RUNNING:
                self.logger.warning("Exiting the 'for log_file_name' loop in start_log_processing function.")
                break
            if LogsFileIndex.validate_log_file_format(str(log_file_name.rstrip('\r\n'))):
                try:
                    res = self.pool.apply_async(self.handle_file, (log_file_name,), callback=self.update_index)
                    res.wait(15)
                except Exception as e:
                    self.logger.error("start_log_processing {}".format(e))
                    break
        self.logger.debug("It took {} seconds to download {} files.".format(time.perf_counter() - self._start_total,
                                                                            additions.__len__()))
        # Get the missed indexes where we had issue, downloading or processing.
        self.log_missed_indexes()
    """
    Check the currently downloaded "LOGS.INDEX" against the local complete.log and remove items that no longer exist
    prior to the first item in the "LOGS.INDEX"
    """

    def update_complete_file(self, completed):
        self.logger.info("Update the complete.log with downloaded file(s).")
        with open(os.path.join(self.config_path, "complete.log"), "wt", encoding="utf-8") as fw:
            for item in completed:
                try:
                    fw.writelines("{}\n".format(item.split(".")[0].split("_")[1]))
                except OSError as e:
                    self.logger.error("Updating file {}.".format(os.path.join(self.config_path, "complete.log"), e))



    """
    Update the complete.log with the last downloaded log.
    """

    def update_index(self, result):
        if result[0]:
            self.logger.info("Downloaded {}".format(result[1]))
            current_index = self.logs_file_index.indexed_logs()
            if result[1] in current_index:
                self.downloaded.append(result[1])
                self.update_complete_file(self.downloaded)
        else:
            self.logger.error("Downloading {}".format(result[1]))

    def handle_file(self, logfile) -> tuple:
        # if the downloader was stopped
        if not self.RUNNING:
            self.logger.warning("Shutting down handle_file function.")
            return False, logfile
        else:
            # download the file
            result = self.download_log_file(logfile)
            # if we got it
            if result[0] == "OK":
                try:
                    # we decrypt the file
                    decrypted_file = self.decrypt_file(result[1], logfile)
                    # handle the decrypted content
                    self.handle_log_decrypted_content(logfile, decrypted_file)
                    return True, logfile
                # if an exception occurs during the decryption or handling the decrypted content,
                # we save the raw file to a "fail" folder
                except Exception as e:
                    self.logger.error("Saving file %s locally: %s %s", logfile, e, traceback.format_exc())
            else:
                self.logger.error("Downloading file %s.", logfile)
                return False, logfile
    """
    Saves the decrypted file content to a log file in the filesystem
    """

    def handle_log_decrypted_content(self, filename, decrypted_file):
        decrypted_file = decrypted_file.decode('utf-8')
        if not os.path.exists(os.path.join(self.config.INCOMING_DIR, "{}.tmp".format(filename))):
            with open(os.path.join(self.config.INCOMING_DIR, "{}.tmp".format(filename)), "wt", encoding="utf-8") as local_file:
                local_file.writelines(decrypted_file)
            os.rename(os.path.join(os.path.join(self.config.INCOMING_DIR, "{}.tmp".format(filename))),
                      os.path.join(self.config.PROCESS_DIR, filename))
            self.logger.info("File %s saved successfully", os.path.join(self.config.PROCESS_DIR, filename))
        else:
            self.logger.warning("{} already exist in {}".format(filename, self.config.PROCESS_DIR))

    """
    Decrypt a file content
    """

    def decrypt_file(self, file_content, filename):
        # each log file is built from a header section and a content section, the two are divided by a |==| mark
        file_split_content = file_content.split(b"|==|\n")

        # Formats other than CEF, LEEF, and W3C do not contain headers.
        # These formats also do not require decryption or decompression.
        if len(file_split_content) != 2:
            self.logger.info("File %s is not encrypted/compressed, returning the content as is.", filename)
            return file_content

        # get the header section content
        file_header_content = file_split_content[0].decode('utf-8')
        # get the log section content
        file_log_content = file_split_content[1]
        # if the file is not encrypted - the "key" value in the file header is '-1'
        file_encryption_key = file_header_content.find("key:")

        if file_encryption_key == -1:
            # uncompress the log content
            try:
                uncompressed_and_decrypted_file_content = zlib.decompressobj().decompress(file_log_content)
            except zlib.error:
                uncompressed_and_decrypted_file_content = file_log_content

        # if the file is encrypted
        else:
            content_encrypted_sym_key = file_header_content.split("key:")[1].splitlines()[0]
            # we expect to have a 'keys' folder that will have the stored private keys
            self.logger.info('Keys Dir: %s', os.path.join(self.config_path, "keys"))
            if not os.path.exists(os.path.join(self.config_path, "keys")):
                self.logger.error("No encryption keys directory was found and file %s is encrypted", filename)
                raise Exception("No encryption keys directory was found")
            # get the public key id from the log file header
            public_key_id = file_header_content.split("publicKeyId:")[1].splitlines()[0]
            # get the public key directory in the filesystem - each time we upload a new key this id is incremented
            public_key_directory = os.path.join(os.path.join(self.config_path, "keys"), public_key_id)
            # if the key directory does not exists
            if not os.path.exists(public_key_directory):
                self.logger.error("Failed to find a proper certificate for : %s who has the publicKeyId of %s",
                                  filename, public_key_id)
                raise Exception("Failed to find a proper certificate")
            # get the checksum
            checksum = file_header_content.split("checksum:")[1].splitlines()[0]

            # get the private key
            private_key = open(os.path.join(public_key_directory, "Private.key"), "rb").read()

            try:
                from M2Crypto import RSA
                from Crypto.Cipher import AES
                rsa_private_key = RSA.load_key_string(private_key)
                content_decrypted_sym_key = rsa_private_key.private_decrypt(
                    base64.b64decode(bytes(content_encrypted_sym_key, 'utf-8')), RSA.pkcs1_padding)
                decrypted_file_content = AES.new(base64.b64decode(bytearray(content_decrypted_sym_key)), AES.MODE_CBC,
                                                 16 * b'\x00').decrypt(file_log_content)
            except Exception as e:
                self.logger.error("Error while trying to decrypt the file %s: %s", filename, e)
                raise Exception("Error while trying to decrypt the file" + filename)
            try:
                uncompressed_and_decrypted_file_content = zlib.decompressobj().decompress(decrypted_file_content)
            except zlib.error:
                uncompressed_and_decrypted_file_content = decrypted_file_content
        return uncompressed_and_decrypted_file_content

    """
    Downloads a log file
    """

    def download_log_file(self, filename):
        # get the file name
        filename = str(filename.rstrip("\r\n"))
        try:
            # download the file
            file_content = self.file_downloader.request_file_content(self.config.BASE_URL + filename)
            # if we received a valid file content
            if file_content != "":
                return "OK", file_content
            # if the file was not found
            else:
                return "NOT_FOUND", file_content
        except Exception:
            self.logger.error("Error while trying to download file")
            return "ERROR"

    """
    Validates a checksum
    """

    @staticmethod
    def validate_checksum(checksum, uncompressed_and_decrypted_file_content):
        m = hashlib.md5()
        m.update(uncompressed_and_decrypted_file_content)
        if m.hexdigest() == checksum:
            return True
        else:
            return False

    """
    Handle a case of process termination
    """

    def set_signal_handling(self, sig, frame):
        current_threads = active_count()
        if sig == signal.SIGINT.value:
            self.logger.info("Got a termination signal, will now shutdown and exit gracefully")

            self.logger.debug("Terminating {} worker threads in thread pool.".format(current_threads))
            if self.config.SYSLOG_ENABLE == 'YES' or self.config.SPLUNK_HEC == 'YES':
                self.file_watcher.RUNNING = False
                self.logger.warning("File Watcher Pool Running set to False.")
                self.file_watcher.pool.terminate()
                self.logger.warning("File Watcher Pool Terminated.")
                self.file_watcher.pool.join()
                self.logger.warning("File Watcher Pool Joined.")
            self.RUNNING = False
            self.logger.warning("Pool Set to False.")
            self.pool.terminate()
            self.logger.warning("Pool Terminated.")
            self.pool.join()
            self.logger.warning("Pool Joined.")
            self.logger.debug("Thread worker pool termination complete")

            while active_count() > 1:
                time.sleep(1)
            self.logger.debug("Shutdown Complete.")

    """
    Gets the next log file name that we should download
    """

    @staticmethod
    def get_counter_from_file_name(file_name):
        curr_log_file_name_arr = file_name.split("_")
        return int(curr_log_file_name_arr[1].rstrip(".log"))

    def get_missed_indexes(self) -> list:
        if not os.path.exists(os.path.join(self.config_path, "complete.log")):
            return []
        with open(os.path.join(self.config_path, "complete.log"), "rb") as fp:
            content = fp.read().decode("utf-8")
            lst = list(map(int, content.splitlines()))
            lst.sort()
        return sorted(set(range(lst[0], lst[-1])) - set(lst))

    def log_missed_indexes(self):
        missed_index = self.get_missed_indexes()
        self.logger.debug("Updating missed_indexes with {} indexes.".format(missed_index.__len__()))
        account_id = self.config.BASE_URL.split("/")[3].split("_")[0]
        with open(os.path.join(self.config_path, "missed_indexes.log"), "wt", encoding="utf-8") as fp:
            for index in missed_index:
                fp.write("{}: {}_{}.log\n".format(datetime.datetime.utcnow(), account_id, index))

    def get_indexed(self) -> list:
        if not os.path.exists(os.path.join(self.config_path, "complete.log")):
            return []
        lst = []
        account_id = self.config.BASE_URL.split("/")[3].split("_")[0]
        with open(os.path.join(self.config_path, "complete.log"), "rb") as fp:
            content = fp.read().decode("utf-8")
        for index in content.splitlines():
            lst.append("{}_{}.log".format(account_id, index))
        return lst


if __name__ == "__main__":
    # default paths
    path_to_config_folder = "/etc/incapsula/logs/config"
    path_to_system_logs_folder = "/var/log/incapsula/logsDownloader/"
    # default log level
    system_logs_level = "INFO"
    # read arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'c:l:v:h', ['configpath=', 'logpath=', 'loglevel=', 'help'])
    except getopt.GetoptError:
        print("Error starting Logs Downloader. The following arguments should be provided:" \
              " \n '-c' - path to the config folder" \
              " \n '-l' - path to the system logs folder" \
              " \n '-v' - LogsDownloader system logs level" \
              " \n Or no arguments at all in order to use default paths")
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('LogsDownloader.py -c <path_to_config_folder> -l <path_to_system_logs_folder> -v <system_logs_level>')
            sys.exit(2)
        elif opt in ('-c', '--configpath'):
            path_to_config_folder = arg
        elif opt in ('-l', '--logpath'):
            path_to_system_logs_folder = arg
        elif opt in ('-v', '--loglevel'):
            system_logs_level = arg.upper()
            if system_logs_level not in ["DEBUG", "INFO", "ERROR"]:
                sys.exit("Provided system logs level is not supported. Supported levels are DEBUG, INFO and ERROR")
    # init the LogsDownloader
    logsDownloader = LogsDownloader(path_to_config_folder, path_to_system_logs_folder, system_logs_level)
    # set a handler for process termination
    signal.signal(signal.SIGINT, logsDownloader.set_signal_handling)


    try:
        # start a dedicated thread that will run the LogsDownloader logs fetching logic
        process_thread = threading.Thread(target=logsDownloader.get_index_file, name="process_thread", daemon=True)
        # start the thread
        process_thread.start()
        while process_thread.is_alive():
            time.sleep(5)
        exit(0)
    except Exception:
        sys.exit("Error starting Logs Downloader - %s" % traceback.format_exc())
