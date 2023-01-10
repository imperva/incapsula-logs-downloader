import time

import urllib3
from urllib3 import exceptions


class HttpClient:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

        self.url = self.config.SPLUNK_HEC_IP
        self.port = self.config.SPLUNK_HEC_PORT
        self.token = self.config.SPLUNK_HEC_TOKEN

        self.hostname = self.config.SPLUNK_HEC_SRC_HOSTNAME
        self.index = self.config.SPLUNK_HEC_INDEX
        self.source = self.config.SPLUNK_HEC_SOURCE
        self.sourcetype = self.config.SPLUNK_HEC_SOURCETYPE


        # Build Full URL out of Parameters
        self.full_url = self.url + ':' + self.port + 'services/collector/event'

        # Create URLLib3 Pool Manager
        self.http = urllib3.PoolManager()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.logger.debug("Send to SPLUNK Host={} on Port={} \n URL: {}".format(self.url, self.port, self.full_url))

    def send(self, message):
        try:
            _time = int(str.split(message, "start=")[1].split(" ")[0])
        except ValueError:
            _time = time.time()
        params = {
            "time": _time,
            "host": self.hostname,
            "index": self.index,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "event": message
        }
        try:
            r = self.http.request('POST', self.full_url, body=params,
                                  headers={'Content-Type': 'application/json', 'Authorization': 'Splunk ' + self.token})
            return True if 299 > r.status > 199 else None
        except exceptions.HTTPError as e:
            raise e
