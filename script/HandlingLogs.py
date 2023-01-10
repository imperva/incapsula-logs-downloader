from SyslogClient import SyslogClient
from HttpClient import HttpClient
import signal
import os
import time


class HandlingLogs:
    running = True

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

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
                files = os.listdir(self.config.PROCESS_DIR)
                if len(files) > 0:
                    for file in files:
                        if not file.__contains__("tmp"):
                            if os.path.isfile(os.path.join(self.config.PROCESS_DIR, file)):
                                self.send_file(os.path.join(self.config.PROCESS_DIR, file))
                                self.logger.info("Sent all messages, deleting {}"
                                                 .format(os.path.join(self.config.PROCESS_DIR, file)))
                                os.remove(os.path.join(self.config.PROCESS_DIR, file))
                        time.sleep(3)
                else:
                    time.sleep(3)
            except OSError as e:
                self.logger.error("Handling content for {}: {}".format(self.config.PROCESS_DIR, e))

    def send_file(self, file):
        with open(file, "r") as fp:
            try:
                messages = fp.readlines()
                self.logger.info("Number of messages added: {}".format(len(messages)))
            except OSError as e:
                self.logger.error("Reading content for {}: {}".format(fp, e))
                raise e

        with open(file, "w") as fp:
            for number, line in enumerate(messages):
                if self.remote_logger is not None:
                    try:
                        if self.remote_logger.send(line):
                            fp.write(line)
                    except OSError as e:
                        retries = 1
                        self.logger.error("Sending line number {} from file {}.".format(number, file, e))
                        while True:
                            try:
                                if self.remote_logger.send(line):
                                    break
                            except OSError:
                                self.logger.warning("Unable to send line number {} from file {} after {} retries."
                                                    .format(number, file, retries))
                                retries += 1
                                time.sleep(5)

    def set_signal_handling(self, sig, frame):
        if sig == signal.SIGTERM:
            self.running = False
            self.logger.info("Got a termination signal, will now shutdown and exit gracefully")

