from SyslogClient import SyslogClient
from SyslogClientCustom import SyslogClientCustom
from HttpClient import HttpClient
import os
import time
from multiprocessing.pool import ThreadPool

# Creating a file watcher that will identify the downloaded logs in the configured
# directory. This file watcher will handle the new file and send to the selected sender.


class HandlingLogs:
    SEND_GOOD = True
    RUNNING = True
    _start = None
    pool = ThreadPool()

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        logger.info("SYSLOG_PROTO: {}".format(self.config.SYSLOG_PROTO))
        logger.info("SYSLOG_CUSTOM: {}".format(self.config.SYSLOG_CUSTOM))

        # Confire the selected sender, either SysLog (TCP or UDP) or Splunk HEC.
        if self.config.SYSLOG_PROTO == 'TCP' and self.config.SYSLOG_ENABLE == 'YES' and self.config.SYSLOG_CUSTOM == 'NO':
            self.logger.info('Syslog enabled, using TCP')
            self.remote_logger = SyslogClient(self.config.SYSLOG_ADDRESS, self.config.SYSLOG_PORT, "TCP", self.logger)

        if (self.config.SYSLOG_PROTO == 'TCP' and self.config.SYSLOG_ENABLE == 'YES'
                and self.config.SYSLOG_CUSTOM == 'NO' and self.config.IMPERVA_SYSLOG_SECURE == "YES"):
            self.logger.info('Syslog enabled, using TCP/TLS')
            self.remote_logger = SyslogClient(self.config.SYSLOG_ADDRESS, self.config.SYSLOG_PORT, "TCP",
                                              self.logger, True)

        if self.config.SYSLOG_PROTO == 'UDP' and self.config.SYSLOG_ENABLE == 'YES' and self.config.SYSLOG_CUSTOM == 'NO':
            self.logger.info('Syslog enabled, using UDP')
            self.remote_logger = SyslogClient(self.config.SYSLOG_ADDRESS, self.config.SYSLOG_PORT, "UDP", self.logger)
        
        if self.config.SYSLOG_PROTO == 'UDP' and self.config.SYSLOG_ENABLE == 'YES' and self.config.SYSLOG_CUSTOM == 'YES':
            self.logger.info('Custom Syslog enabled, using UDP')
            self.remote_logger = SyslogClientCustom(self.config.SYSLOG_ADDRESS, self.config.SYSLOG_PORT, "UDP", self.logger, self.config.SYSLOG_SENDER_HOSTNAME)

        if self.config.SYSLOG_PROTO == 'TCP' and self.config.SYSLOG_ENABLE == 'YES' and self.config.SYSLOG_CUSTOM == 'YES':
            self.logger.info('Custom Syslog enabled, using TCP')
            self.remote_logger = SyslogClientCustom(self.config.SYSLOG_ADDRESS, self.config.SYSLOG_PORT, "TCP", self.logger, self.config.SYSLOG_SENDER_HOSTNAME)

        if (self.config.SYSLOG_PROTO == 'TCP' and self.config.SYSLOG_ENABLE == 'YES'
                and self.config.SYSLOG_CUSTOM == 'YES' and self.config.IMPERVA_SYSLOG_SECURE == "YES"):
            self.logger.info('Custom Syslog enabled, using TCP/TLS')
            self.remote_logger = SyslogClientCustom(self.config.SYSLOG_ADDRESS, self.config.SYSLOG_PORT, "TCP",
                                                    self.logger, self.config.SYSLOG_SENDER_HOSTNAME, True)

        if self.config.SPLUNK_HEC == "YES":
            self.logger.info('Splunk HEC enabled.')
            self.remote_logger = HttpClient(self.config, self.logger)

    def watch_files(self):
        while self.RUNNING:
            try:
                # Loop over the configured processing directory
                files = os.listdir(self.config.PROCESS_DIR)

                if len(files) > 0:
                    for file in files:
                        if not self.RUNNING:
                            self.logger.warning("Exiting the 'for file' loop in watch_files function.")
                            break
                        self._start = time.perf_counter()
                        if self.pool is None:
                            self.logger.warning("No file_watcher pool, exiting the watch_files function.")
                            break
                        try:
                            res = self.pool.apply_async(self.send_file, (file,), callback=self.update_index)
                            res.wait(15)
                        except Exception as e:
                            self.logger.error("watch_files {}".format(e))
                            break
                else:
                    time.sleep(3)
            except OSError as e:
                self.logger.error("Handling content for {}: {}".format(self.config.PROCESS_DIR, e))
        self.logger.warning("Shutting down watch_files.")

    # Send the contents of the found file to the configured remote logging endpoint.
    def send_file(self, file) -> tuple:
        messages = None
        if not os.path.isfile(os.path.join(self.config.PROCESS_DIR, file)) and not self.SEND_GOOD:
            return False, file
        else:
            file_path = os.path.join(self.config.PROCESS_DIR, file)
            with open(file_path, "r") as fp:
                try:
                    # Get all the lines from the file
                    messages = fp.readlines()
                    if not len(messages) > 0:
                        self.logger.warning("No messages added for {}".format(file))
                        return False, file
                except OSError as e:
                    self.logger.error("Reading content for {}: {}".format(fp, e))
                    return False, file

            if self.remote_logger is not None:
                self.logger.info("Number of messages added: {}".format(len(messages)))
                # Sent the array of message to the remote logger
                if self.remote_logger.send(messages):
                    # Archive the log if sent successfully
                    if bool(self.config.ARCHIVE_DIR):
                        self.archive_log(file_path, file)
                    else:
                        self.delete_log(file_path)
                    return True, file
                else:
                    # Go into a failed state and keep trying to send.
                    self.SEND_GOOD = False
                    self.logger.warning("-----Changing SEND_GOOD to {}--------".format(self.SEND_GOOD))
                    self.logger.warning("Failed to send {} lines from {}."
                                        .format(len(messages), file_path))
                    retries = 1
                    while self.RUNNING:
                        self.logger.warning(f"We failed to send and will continue to retry on file {file_path}.")
                        try:
                            if self.remote_logger.send(messages):
                                self.SEND_GOOD = True
                                self.logger.warning("-----Changing SEND_GOOD to {}--------"
                                                    .format(self.SEND_GOOD))
                                # Archive the log if sent successfully
                                if bool(self.config.ARCHIVE_DIR):
                                    self.archive_log(file_path, file)
                                else:
                                    self.delete_log(file_path)
                                return True, file
                            else:
                                retries += 1
                                time.sleep(5)
                        except:
                            self.logger.warning("Unable to send lines from file {} after {} retries."
                                                .format(file, retries))
                            retries += 1
                            time.sleep(5)


    def update_index(self, result):
        if result:
            try:
                if result[0]:
                    self.logger.debug("Took {} seconds to send {}.".format(time.perf_counter() - self._start, result[1]))
                    output = result[1]
                    output = output.split(".")[0].split("_")[1]
                    with open(os.path.join(self.config.config_path, "sent.log"), "at", encoding="utf-8") as fp:
                        fp.write("{}\n".format(output))
                else:
                    self.logger.error("Sending {}".format(result[1]))
            except Exception as e:
                self.logger.error(" updating sent.log index. {}".format(e))
        else:
            self.logger.warning(", nothing returned from file send function.")

    def archive_log(self, original, file):
        # Archive the log if sent successfully
        import gzip
        self.logger.debug("----Let's compress and archive {}".format(original))
        try:
            if not os.path.exists(self.config.ARCHIVE_DIR):
                os.makedirs(self.config.ARCHIVE_DIR)
            with open(original, "rb") as of:
                original_data = of.read()
            with gzip.open(os.path.join(self.config.ARCHIVE_DIR, file + ".gz"), "wb") as compress_data:
                compress_data.write(original_data)
            self.logger.info("Sent all messages, compressing and archiving {} to {}."
                             .format(original, os.path.join(self.config.ARCHIVE_DIR, file + ".gz")))
            os.remove(original)
        except (FileNotFoundError, PermissionError, OSError) as e:
            self.logger.error("Archiving file {} - {}".format(file, e))

    def delete_log(self, file):
        try:
            os.remove(file)
            self.logger.info("Deleted {}".format(file))
        except (FileNotFoundError, PermissionError, OSError) as e:
            self.logger.error("Deleting file {} - {}".format(file, e))
