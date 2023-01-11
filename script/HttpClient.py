import json
import time
import urllib3
import requests
from urllib3 import exceptions
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


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
        self.full_url = self.url + ':' + self.port + '/services/collector/event'

        # Create URLLib3 Pool Manager
        self.http = urllib3.PoolManager()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.logger.debug("Send to SPLUNK Host={} on Port={} \n URL: {}".format(self.url, self.port, self.full_url))

        retry_strategy = Retry(
            total=3,
            status_forcelist=[429],
            backoff_factor=2
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", adapter)

    def send(self, data):
        messages = []

        for message in data:
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

            messages.append(params)
        body = json.dumps(messages)

        try:
            response = self.session.post(url=self.full_url, data=body, timeout=(5, 15), verify=False,
                                         headers={'Content-Type': 'application/json',
                                                  'Authorization': 'Splunk ' + self.token})
            if 299 > response.status_code > 199:
                return True
            else:
                self.logger.error("{} return status code: {}\n{}".format(self.url, response.status_code, response.text))
                return None
        except requests.HTTPError as e:
            self.logger.error(e)
        except requests.ConnectionError as e:
            self.logger.error(e)
        except requests.Timeout as e:
            self.logger.error(e)
        except requests.RequestException as e:
            self.logger.error(e)


