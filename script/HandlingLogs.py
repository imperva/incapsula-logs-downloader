from SyslogClient import SyslogClient
from HttpClient import HttpClient
import signal
import os
import time
import asyncio


# Creating a file watcher that will identify the downloaded logs in the configured
# directory. This file watcher will handle the new file and send to the selected sender.
class HandlingLogs:
    SEND_GOOD = True
    running = True

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

        # Confire the selected sender, either SysLog (TCP or UDP) or Splunk HEC.
        if self.config.SYSLOG_PROTO == 'TCP' and self.config.SYSLOG_ENABLE == 'YES':
            self.logger.info('Syslog enabled, using TCP')
            self.remote_logger = SyslogClient(self.config.SYSLOG_ADDRESS, self.config.SYSLOG_PORT, "TCP", self.logger)

        if self.config.SYSLOG_PROTO == 'UDP' and self.config.SYSLOG_ENABLE == 'YES':
            self.logger.info('Syslog enabled, using UDP')
            self.remote_logger = SyslogClient(self.config.SYSLOG_ADDRESS, self.config.SYSLOG_PORT, "UDP", self.logger)

        if self.config.SPLUNK_HEC == "YES":
            self.logger.info('Splunk HEC enabled.')
            self.remote_logger = HttpClient(self.config, self.logger)

    def watch_files(self):
        time.sleep(5)
        while self.running:
            try:
                # Loop over the configured processing directory
                files = os.listdir(self.config.PROCESS_DIR)
                if len(files) > 0:
                    for file in files:
                        if os.path.isfile(os.path.join(self.config.PROCESS_DIR, file)):
                            if not file.__contains__("tmp") and self.SEND_GOOD:
                                # If this is a file that we are looking for, send the file.
                                _start = time.perf_counter()
                                asyncio.run(self.send_file(file))
                                self.logger.debug(time.perf_counter() - _start)
                    time.sleep(3)
                else:
                    time.sleep(3)
            except OSError as e:
                self.logger.error("Handling content for {}: {}".format(self.config.PROCESS_DIR, e))

    # Send the contents of the found file to the configured remote logging endpoint.
    async def send_file(self, file):
        original = os.path.join(self.config.PROCESS_DIR, file)
        with open(original, "r") as fp:
            try:
                # Get all the lines from the file
                messages = fp.readlines()
                if len(messages) > 0:
                    self.logger.info("Number of messages added: {}".format(len(messages)))
                    if self.remote_logger is not None:
                        # Sent the array of message to the remote logger
                        if self.remote_logger.send(messages):
                            # Archive the log if sent successfully
                            if self.config.ARCHIVE_DIR is not None:
                                archived = os.path.join(self.config.ARCHIVE_DIR, file)
                                self.logger.info("Sent all messages, archiving {} to {}"
                                                 .format(original, archived))
                                os.rename(original, archived)
                            else:
                                # Delete the log if not archiving
                                self.logger.info("Sent all messages, deleting {}"
                                                 .format(original))
                                os.remove(original)
                        else:
                            # Go into a failed state and keep trying to send.
                            self.SEND_GOOD = False
                            self.logger.warning("-----Changing SEND_GOOD to {}--------".format(self.SEND_GOOD))
                            self.logger.warning("Failed to send {} lines from {}."
                                                .format(len(messages), original))
                            retries = 1
                            while True:
                                try:
                                    if self.remote_logger.send(messages):
                                        self.SEND_GOOD = True
                                        self.logger.warning("-----Changing SEND_GOOD to {}--------"
                                                            .format(self.SEND_GOOD))
                                        break
                                    else:
                                        retries += 1
                                        time.sleep(5)
                                except:
                                    self.logger.warning("Unable to send lines from file {} after {} retries."
                                                        .format(file, retries))
                                    retries += 1
                                    time.sleep(5)
                else:
                    self.logger.warning("No messages added: {}".format(len(messages)))
                    return
            except OSError as e:
                self.logger.error("Reading content for {}: {}".format(fp, e))
                raise e

    def set_signal_handling(self, sig, frame):
        if sig == signal.SIGTERM:
            self.running = False
            self.logger.info("Got a termination signal, will now shutdown and exit gracefully")
