#!/usr/bin/env python
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


import ConfigParser
import base64
import getopt
import hashlib
import logging
import os
import platform
import re
import signal
import sys
import threading
import time
import traceback
import ssl
import urllib2
import zlib
from logging import handlers

import M2Crypto
import loggerglue
import loggerglue.emitter
import loggerglue.logger
from Crypto.Cipher import AES

"""
Main class for downloading log files
"""


class LogsDownloader:

    # the LogsDownloader will run until external termination
    running = True

    def __init__(self, config_path, system_log_path, log_level):
        # set a log file for the downloader
        self.logger = logging.getLogger("logsDownloader")
        # default log directory for the downloader
        log_dir = system_log_path
        # create the log directory if needed
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        # keep logs history for 7 days
        file_handler = logging.handlers.TimedRotatingFileHandler(os.path.join(log_dir, "logs_downloader.log"), when='midnight', backupCount=7)
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        if log_level == "DEBUG":
            self.logger.setLevel(logging.DEBUG)
        elif log_level == "INFO":
            self.logger.setLevel(logging.INFO)
        elif log_level == "ERROR":
            self.logger.setLevel(logging.ERROR)
        self.logger.debug("Initializing LogsDownloader")
        self.config_path = config_path
        self.config_reader = Config(self.config_path, self.logger)
        try:
            # read the configuration file and load it
            self.config = self.config_reader.read()
        except Exception:
            self.logger.error("Exception while getting LogsDownloader config file - Could Not find Configuration file - %s", traceback.format_exc())
            sys.exit("Could Not find Configuration file")
        # create a file downloader handler
        self.file_downloader = FileDownloader(self.config, self.logger)
        # create a last file id handler
        self.last_known_downloaded_file_id = LastFileId(self.config_path)
        # create a logs file index handler
        self.logs_file_index = LogsFileIndex(self.config, self.logger, self.file_downloader)
        # create log folder if needed for storing downloaded logs
        if self.config.SAVE_LOCALLY == "YES":
            if not os.path.exists(self.config.PROCESS_DIR):
                os.makedirs(self.config.PROCESS_DIR)
        self.logger.info("LogsDownloader initializing is done")

    """
    Download the log files.
    If this is the first time, we get the logs.index file, scan it, and download all of the files in it.
    It this is not the first time, we try to fetch the next log file.
    """
    def get_log_files(self):
        retries = 0
        while self.running:
            # check what is the last log file that we downloaded
            last_log_id = self.last_known_downloaded_file_id.get_last_log_id()
            # if there is no last downloaded file
            if last_log_id == "":
                    self.logger.info("No last downloaded file is found - downloading index file and starting to download all the log files in it")
                    try:
                        # download the logs.index file
                        self.logs_file_index.download()
                        # scan it and download all of the files in it
                        self.first_time_scan()
                    except Exception, e:
                        self.logger.error("Failed to downloading index file and starting to download all the log files in it - %s, %s", e.message, traceback.format_exc())
                        # wait for 30 seconds between each iteration
                        self.logger.info("Sleeping for 30 seconds before trying to fetch logs again...")
                        time.sleep(30)
                        continue
            # the is a last downloaded log file id
            else:
                self.logger.debug("The last known downloaded file is %s", last_log_id)
                # get the next log file name that we should download
                next_file = self.last_known_downloaded_file_id.get_next_file_name()
                self.logger.debug("Will now try to download %s", next_file)
                try:
                    # download and handle the next log file
                    success = self.handle_file(next_file)
                    # if we successfully handled the next log file
                    if success:
                        self.logger.debug("Successfully handled file %s, updating the last known downloaded file id", next_file)
                        # set the last handled log file information
                        self.last_known_downloaded_file_id.move_to_next_file()
                        if self.running:
                            self.logger.info("Sleeping for 2 seconds before fetching the next logs file")
                            retries = 0
                            time.sleep(2)

                    # we failed to handle the next log file
                    else:
                        self.logger.info("Could not get log file %s. It could be that the log file does not exist yet.", next_file)
                        if self.running:
                            if retries >= 10:
                                self.logger.info("Failed to download file 10 times, trying to recover.")
                                # download the logs.index file
                                self.logs_file_index.download()
                                logs_in_index = self.logs_file_index.indexed_logs()
                                log_id = self.get_counter_from_file_name(next_file)
                                first_log_id_in_index = self.get_counter_from_file_name(logs_in_index[0])
                                if log_id < first_log_id_in_index:
                                    self.logger.error("Current downloaded file is not in the index file any more. This is probably due to a long delay in downloading. Attempting to recover")
                                    self.last_known_downloaded_file_id.remove_last_log_id()
                                elif self.last_known_downloaded_file_id.get_next_file_name(skip_files=1) in logs_in_index:
                                    self.logger.warning("Skipping " + next_file)
                                    self.last_known_downloaded_file_id.move_to_next_file()
                                else:
                                    self.logger.info("Next file still does not exist. Sleeping for 30 seconds and continuing normally")
                                    retries = 0
                                    time.sleep(30)
                            else:
                                # wait for 30 seconds between each iteration
                                self.logger.info("Sleeping for 30 seconds before trying to fetch logs again...")
                                retries += 1
                                time.sleep(30)

                except Exception, e:
                        self.logger.error("Failed to download file %s. Error is - %s , %s", next_file, e.message, traceback.format_exc())

    """
    Scan the logs.index file, and download all the log files in it
    """
    def first_time_scan(self):
        self.logger.info("No last index found, will now scan the entire index...")
        # get the list of file names from the index file
        logs_in_index = self.logs_file_index.indexed_logs()
        # for each file
        for log_file_name in logs_in_index:
            if self.running:
                if LogsFileIndex.validate_log_file_format(str(log_file_name.rstrip('\r\n'))):
                    # download and handle the log file
                    success = self.handle_file(log_file_name)
                    # if we successfully handled the log file
                    if success:
                        # set the last handled log file information
                        self.last_known_downloaded_file_id.update_last_log_id(log_file_name)
                    else:
                        # skip the file and try to get the next one
                        self.logger.warning("Skipping File %s", log_file_name)
        self.logger.info("Completed fetching all the files from the logs files index file")

    """
    Download a log file, decrypt, unzip, and store it
    """
    def handle_file(self, logfile, wait_time=5):
        # we will try to get the file a max of 3 tries
        counter = 0
        while counter <= 3:
            if self.running:
                # download the file
                result = self.download_log_file(logfile)
                # if we got it
                if result[0] == "OK":
                    try:
                        # we decrypt the file
                        decrypted_file = self.decrypt_file(result[1], logfile)
                        # handle the decrypted content
                        self.handle_log_decrypted_content(logfile, decrypted_file)
                        self.logger.info("File %s download and processing completed successfully", logfile)
                        return True
                    # if an exception occurs during the decryption or handling the decrypted content,
                    # we save the raw file to a "fail" folder
                    except Exception, e:
                        self.logger.info("Saving file %s locally to the 'fail' folder %s %s", logfile, e.message, traceback.format_exc())
                        fail_dir = os.path.join(self.config.PROCESS_DIR, 'fail')
                        if not os.path.exists(fail_dir):
                            os.mkdir(fail_dir)
                        with open(os.path.join(fail_dir, logfile), "w") as file:
                            file.write(result[1])
                        self.logger.info("Saved file %s locally to the 'fail' folder", logfile)
                        break
                # if the file is not found (could be that it is not generated yet)
                elif result[0] == "NOT_FOUND" or result[0] == "ERROR":
                    # we increase the retry counter
                    counter += 1
                # if we want to sleep between retries
                if wait_time > 0 and counter <= 3:
                    if self.running:
                        self.logger.info("Sleeping for %s seconds until next file download retry number %s out of 3", wait_time, counter)
                        time.sleep(wait_time)
            # if the downloader was stopped
            else:
                return False
        # if we didn't succeed to download the file
        return False

    """
    Saves the decrypted file content to a log file in the filesystem
    """
    def handle_log_decrypted_content(self, filename, decrypted_file):
        if self.config.SYSLOG_ENABLE == 'YES':
            for msg in decrypted_file.splitlines():
                if msg != '':
                    emit = loggerglue.emitter.UDPSyslogEmitter((self.config.SYSLOG_ADDRESS, int(self.config.SYSLOG_PORT)))
                    emit.emit(msg)
        if self.config.SAVE_LOCALLY == "YES":
            local_file = open(self.config.PROCESS_DIR + filename, "a+")
            local_file.writelines(decrypted_file)

    """
    Decrypt a file content
    """
    def decrypt_file(self, file_content, filename):
        # each log file is built from a header section and a content section, the two are divided by a |==| mark
        file_split_content = file_content.split("|==|\n")
        # get the header section content
        file_header_content = file_split_content[0]
        # get the log section content
        file_log_content = file_split_content[1]
        # if the file is not encrypted - the "key" value in the file header is '-1'
        file_encryption_key = file_header_content.find("key:")
        if file_encryption_key == -1:
            # uncompress the log content
            uncompressed_and_decrypted_file_content = zlib.decompressobj().decompress(file_log_content)
        # if the file is encrypted
        else:
            content_encrypted_sym_key = file_header_content.split("key:")[1].splitlines()[0]
            # we expect to have a 'keys' folder that will have the stored private keys
            if not os.path.exists(os.path.join(self.config_path, "keys")):
                self.logger.error("No encryption keys directory was found and file %s is encrypted", filename)
                raise Exception("No encryption keys directory was found")
            # get the public key id from the log file header
            public_key_id = file_header_content.split("publicKeyId:")[1].splitlines()[0]
            # get the public key directory in the filesystem - each time we upload a new key this id is incremented
            public_key_directory = os.path.join(os.path.join(self.config_path, "keys"), public_key_id)
            # if the key directory does not exists
            if not os.path.exists(public_key_directory):
                self.logger.error("Failed to find a proper certificate for : %s who has the publicKeyId of %s", filename, public_key_id)
                raise Exception("Failed to find a proper certificate")
            # get the checksum
            checksum = file_header_content.split("checksum:")[1].splitlines()[0]
            # get the private key
            private_key = open(os.path.join(public_key_directory, "Private.key"), "r").read()
            try:
                rsa_private_key = M2Crypto.RSA.load_key_string(private_key)
                content_decrypted_sym_key = rsa_private_key.private_decrypt(base64.b64decode(bytearray(content_encrypted_sym_key)), M2Crypto.RSA.pkcs1_padding)
                uncompressed_and_decrypted_file_content = zlib.decompressobj().decompress(AES.new(base64.b64decode(bytearray(content_decrypted_sym_key)), AES.MODE_CBC, 16 * "\x00").decrypt(file_log_content))
                # we check the content validity by checking the checksum
                content_is_valid = self.validate_checksum(checksum, uncompressed_and_decrypted_file_content)
                if not content_is_valid:
                    self.logger.error("Checksum verification failed for file %s", filename)
                    raise Exception("Checksum verification failed")
            except Exception, e:
                self.logger.error("Error while trying to decrypt the file %s", filename, e.message, traceback.format_exc())
                raise Exception("Error while trying to decrypt the file" + filename)
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
        if sig == signal.SIGTERM:
            self.running = False
            self.logger.info("Got a termination signal, will now shutdown and exit gracefully")

    """
    Gets the next log file name that we should download
    """
    def get_counter_from_file_name(self, file_name):
        curr_log_file_name_arr = file_name.split("_")
        return int(curr_log_file_name_arr[1].rstrip(".log"))

"""
****************************************************************
                        Helper Classes
****************************************************************
"""

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
        with open(index_file_path, "w") as index_file:
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


"""

LogsFileIndex - A class for managing the logs files index file

"""


class LogsFileIndex:

    def __init__(self, config, logger, downloader):
        self.config = config
        self.content = None
        self.hash_content = None
        self.logger = logger
        self.file_downloader = downloader

    """
    Gets the indexed log files
    """
    def indexed_logs(self):
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
            if LogsFileIndex.validate_logs_index_file_format(content):
                self.content = content.splitlines()
                self.hash_content = set(self.content)
            else:
                self.logger.error("log.index, Pattern Validation Failed")
                raise Exception
        else:
            raise Exception

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


"""

Config - A class for reading the configuration file

"""


class Config:

    def __init__(self, config_path, logger):
        self.config_path = config_path
        self.logger = logger

    """
    Reads the configuration file
    """
    def read(self):
        config_file = os.path.join(self.config_path, "Settings.Config")
        if os.path.exists(config_file):
            config_parser = ConfigParser.ConfigParser()
            config_parser.read(config_file)
            config = Config(self.config_path, self.logger)
            config.API_ID = config_parser.get("SETTINGS", "APIID")
            config.API_KEY = config_parser.get("SETTINGS", "APIKEY")
            config.PROCESS_DIR = os.path.join(config_parser.get("SETTINGS", "PROCESS_DIR"), "")
            config.BASE_URL = os.path.join(config_parser.get("SETTINGS", "BASEURL"), "")
            config.SAVE_LOCALLY = config_parser.get("SETTINGS", "SAVE_LOCALLY")
            config.USE_PROXY = config_parser.get("SETTINGS", "USEPROXY")
            config.PROXY_SERVER = config_parser.get("SETTINGS", "PROXYSERVER")
            config.SYSLOG_ENABLE = config_parser.get('SETTINGS', 'SYSLOG_ENABLE')
            config.SYSLOG_ADDRESS = config_parser.get('SETTINGS', 'SYSLOG_ADDRESS')
            config.SYSLOG_PORT = config_parser.get('SETTINGS', 'SYSLOG_PORT')
            config.USE_CUSTOM_CA_FILE = config_parser.get('SETTINGS', 'USE_CUSTOM_CA_FILE')
            config.CUSTOM_CA_FILE = config_parser.get('SETTINGS', 'CUSTOM_CA_FILE')
            return config
        else:
            self.logger.error("Could Not find configuration file %s", config_file)
            raise Exception("Could Not find configuration file")


"""

FileDownloader - A class for downloading files

"""


class FileDownloader:

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    """
    A method for getting a destination URL file content
    """
    def request_file_content(self, url, timeout=20):
        # default value
        response_content = ""
        # if we are using a proxy server - read its configurations
        if self.config.USE_PROXY == "YES":
            proxy_dict = {"http": self.config.PROXY_SERVER, "https": self.config.PROXY_SERVER, "ftp": self.config.PROXY_SERVER}
            proxy = urllib2.ProxyHandler(proxy_dict)
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
        # build the request
        request = urllib2.Request(url)
        base64string = base64.encodestring("%s:%s" % (self.config.API_ID, self.config.API_KEY)).replace('\n', '')
        request.add_header("Authorization", "Basic %s" % base64string)
        try:
            # open the connection to the URL
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            if self.config.USE_CUSTOM_CA_FILE == "YES":
                response = urllib2.urlopen(request, timeout=timeout, cafile=self.config.CUSTOM_CA_FILE, context=ctx)
            else:
                response = urllib2.urlopen(request, timeout=timeout, context=ctx)
            # if we got a 200 OK response
            if response.code == 200:
                self.logger.info("Successfully downloaded file from URL %s" % url)
                # read the response content
                response_content = response.read()
            # if we got another response code
            else:
                self.logger.error("Failed to download file %s. Response code is %s. Info is %s", url, response.code, response.info())
            # close the response
            response.close()
            # return the content string
            return response_content
        # if we got a 401 or 404 responses
        except urllib2.HTTPError, e:
            if e.code == 404:
                self.logger.warning("Could not find file %s. Response code is %s", url, e.code)
                return response_content
            elif e.code == 401:
                self.logger.error("Authorization error - Failed to download file %s. Response code is %s", url, e.code)
                raise Exception("Authorization error")
            elif e.code == 429:
                self.logger.error("Rate limit exceeded - Failed to download file %s. Response code is %s", url, e.code)
                raise Exception("Rate limit error")
            else:
                self.logger.error("An error has occur while making a open connection to %s. %s", url, str(e.code))
                raise Exception("Connection error")
        # unexpected exception occurred
        except Exception:
            self.logger.error("An error has occur while making a open connection to %s. %s", url, traceback.format_exc())
            raise Exception("Connection error")


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
        print "Error starting Logs Downloader. The following arguments should be provided:" \
              " \n '-c' - path to the config folder" \
              " \n '-l' - path to the system logs folder" \
              " \n '-v' - LogsDownloader system logs level" \
              " \n Or no arguments at all in order to use default paths"
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print 'LogsDownloader.py -c <path_to_config_folder> -l <path_to_system_logs_folder> -v <system_logs_level>'
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
    signal.signal(signal.SIGTERM, logsDownloader.set_signal_handling)
    try:
        # start a dedicated thread that will run the LogsDownloader logs fetching logic
        process_thread = threading.Thread(target=logsDownloader.get_log_files, name="process_thread")
        # start the thread
        process_thread.start()
        while logsDownloader.running:
            time.sleep(1)
        process_thread.join(1)
    except Exception:
        sys.exit("Error starting Logs Downloader - %s" % traceback.format_exc())
