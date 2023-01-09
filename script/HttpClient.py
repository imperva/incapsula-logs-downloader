import urllib3
from urllib3 import exceptions


class HttpClient:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

        self.url = self.config.SPLUNK_HEC_IP
        self.port = self.config.SPLUNK_HEC_PORT
        self.token = self.config.SPLUNK_HEC_TOKEN

        # Build Full URL out of Parameters
        self.full_url = "http://" + self.url + ':' + self.port + '/services/collector/raw'

        # Create URLLib3 Pool Manager
        self.http = urllib3.PoolManager()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.logger.debug("Send to SPLUNK Host={} on Port={} \n URL: {}".format(self.url, self.port, self.full_url))

    def send(self, message):
        try:
            r = self.http.request('POST', self.full_url, body=message,
                                  headers={'Content-Type': 'application/json', 'Authorization': 'Splunk ' + self.token})
            return True if 299 > r.status > 199 else None
        except exceptions.HTTPError as e:
            raise e
