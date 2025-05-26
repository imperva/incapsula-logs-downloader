import json
import requests
import re
from datetime import datetime
from HttpClient import HttpClient

class ElasticClientCustom(HttpClient):
    """
    parse and send logs to Elasticsearch  
    """
    
    def __init__(self, config, logger):
        #super().__init__(config, logger)   # todo: make inheritance work again.  separate HttpClient and  splunk realization to separate classes
        self.logger = logger
        self.es_host = config.ELASTICSEARCH
        self.es_index_pattern = config.ELASTICSEARCH_INDEX_PATTERN
        self.es_username = config.ELASTICSEARCH_USERNAME
        self.es_password = config.ELASTICSEARCH_PASSWORD
        self.es_ssl = config.ELASTICSEARCH_SSL
        protocol = 'https' if self.es_ssl == 'YES' else 'http'
        self.base_url = f"{protocol}://{self.es_host}"
        self.auth = None
        self.es_major_version = None
        if self.es_username and self.es_password:
            self.auth = (self.es_username, self.es_password)
        if self.test_connection():
            self.logger.debug("Send to ELASTICSEARCH={} elastic_login={}\n".format(self.es_host, self.es_username))
            self.logger.debug(f'ELASTICSEARCH version {self.es_major_version}')
        else:
            raise Exception('Failed to initializate ElasticClientCustom')
           
    def send(self, message_data):
        """
        Send messages to Elasticsearch
        remote_logger.send() inteface realization 
        Returns:
            bool: True if success else False
        """
        try:
            # if we have 1 row - make list.
            if isinstance(message_data, str):
                messages = [message_data]
            else:
                messages = message_data
            
            # prepare bulk request
            bulk_data = []
            timestamp = datetime.utcnow()
            
            for msg in messages:
                if not msg or msg.strip() == '':
                    continue

                json_msg = self.message_customize(msg)
                if json_msg == '{}': # skip empty messages
                    continue
                
                try:
                    parsed_msg = json.loads(json_msg)
                    # extract index name from @timestamp
                    if '@timestamp' in parsed_msg:
                        es_index = datetime.strptime(parsed_msg['@timestamp'].split('.')[0], "%Y-%m-%dT%H:%M:%S").strftime(self.es_index_pattern)
                    else:
                        es_index = datetime.strftime(timestamp, self.es_index_pattern)
                        
                    # prepare data for bulk API
                    if self.es_major_version <= 7:
                        bulk_data.append({ "index": {"_index": es_index, "_type": "_doc" } })
                    elif self.es_major_version >= 8:
                        bulk_data.append({ "index": {"_index": es_index } })
                    bulk_data.append(parsed_msg)
                    
                except json.JSONDecodeError as e:
                    self.logger.error(f"JSON parsing error: {e}")
                    continue
            
            if not bulk_data:
                self.logger.error("No valid data for client")
                return True
            
            # actually send bulk request
            return self._send_bulk_request(bulk_data)
            
        except Exception as e:
            self.logger.error(f"Unknown error while send in Elasticsearch: {e}")
            return False
    
    def _send_bulk_request(self, bulk_data):
        """
        Send bulk request to Elasticsearch
        Args:
            bulk_data (list): [{es doc meta}, {es doc data}, {es doc meta}, {es doc data}, ... ]
        Returns:
            bool: True if success ekse False 
        """
        try:
            # prepare body for bulk API
            bulk_body = ""
            for item in bulk_data:
                bulk_body += json.dumps(item) + "\n"
            
            url = f"{self.base_url}/_bulk"
            headers = {
                'Content-Type': 'application/x-ndjson',
                'Accept': 'application/json'
            }
            
            response = requests.post(
                url,
                data=bulk_body,
                headers=headers,
                auth=self.auth,
                timeout=30,
                verify=self.es_ssl
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('errors', False):
                    self.logger.error("Cannot index some logs")
                    for item in result.get('items', []):
                        if 'index' in item and 'error' in item['index']:
                            self.logger.error(f"Errors: {item['index']['error']}")
                    return False
                else:
                    self.logger.debug(f"Success sent {len(bulk_data)//2} docs to Elasticsearch")
                    return True
            else:
                self.logger.error(f"HTTP Error: {response.status_code}, {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error while request to Elasticsearch: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unkonw errror while bulk request: {e}")
            return False
    
    def message_customize(self, msg):
        """
        parse and customize messages here
        put your blackmagic here and return json object for ES
        """
        if msg != '':
            msg = msg.replace("Customer=", "cn101=") 
            msg = msg.replace("cn1=", "cn102=")
            msg = msg.replace("deviceExternalId=", "cn1=")
            msg = msg.replace("xff=", "cs99=") 
            msg = msg.replace("cs4=", "cs98=") 
            msg = msg.replace("cs3=", "cs4=") 
            msg = msg.replace("sourceServiceName=", "cs3=") 
            msg = msg.replace("cs3Label=CO Support", "cs3Label=ServiceName") 
            msg = msg.replace("cs4Label=VID", "cs4Label=CookieSupport")
            msg = msg.replace("cs1Label=Cap Support", "cs1Label=CaptchaSupport") 
            msg = msg.replace("siteTag=", "cs97=") 
            msg = msg.replace("siteid=", "flexNumber1=") 
            msg = msg.replace("spt=", "dpt=") 
            msg = msg.replace("cpt=", "spt=") 
            msg = msg.replace("sip=", "dst=") 
            msg = msg.replace("ref=", "requestContext=") 
            msg = msg.replace("cs6=", "deviceProcessName=")  
            msg = msg.replace("cs5=", "fname=") 
            msg = msg.replace("qstr=", "cs5=") 
            msg = msg.replace("ver=", "cs6=")           
            msg += " cn101Label=Customer"
            msg += " cn102Label=ResponseCode"
            msg += " cs5Label=requestQuery "
            msg += " cs6Label=TLSver "
            msg += " cn1Label=EventId "
            msg += " cs97Label=siteTag "
            msg += " cs98Label=VID "
            msg += " cs99Label=Xff "
        
        if msg.startswith('CEF:0|Incapsula|SIEMintegration|'):
            _, head1, msg = msg.partition('CEF:0|Incapsula|SIEMintegration|')
            v1, _, msg = msg.partition('|')
            v2, _, msg = msg.partition('|')
            rule_name, _, msg = msg.partition('|')
            v3, _, msg = msg.partition('|')
            msgObject = {'v1': v1, 'v2': v2, 'v3': v3, 'ruleName': rule_name}
            kv_list = []
            boundaries = list(re.finditer(r'(\s\w+)=', msg))
            for match, next_ in zip(boundaries, boundaries[1:]):
                s, f = match.start(), next_.start()
                kv_list.append(msg[s:f])
            if boundaries:  # workaround possible error
                kv_list.append(msg[boundaries[-1].start():])
            for kv in kv_list:
                kv = kv.strip()
                k, _, val = kv.partition('=')
                if k:
                    msgObject[k] = val
            # parse timestamp
            if 'end' in msgObject:
                timestamp_s = int(msgObject["end"]) / 1000
                dt_object_utc = datetime.utcfromtimestamp(timestamp_s)
                msgObject["@timestamp"] = dt_object_utc.isoformat(timespec='milliseconds') + "Z"

            # replace separated key-value pairs to key: value type
            # msgObject = {'cn1':'somevalue', 'cn1Label':'Customer'} -> msgObject = {'Customer': 'somevalue'}
            fields = list(msgObject.keys())
            for field in fields:
                if (field.startswith('cn') or field.startswith('cs')) and field[2:].isnumeric() and (field + 'Label') in msgObject:
                    label = msgObject[field + 'Label']
                    msgObject[label] = msgObject[field]
                    del msgObject[field]
                    del msgObject[field + 'Label']

            # convert some types:
            if "latitude" in msgObject and "longitude" in msgObject:
                      msgObject["location"] = (float(msgObject["latitude"]), float(msgObject["longitude"]))
            if "dpt" in msgObject:
                msgObject["dpt"] = int(msgObject["dpt"])
            if "spt" in msgObject:
                msgObject["spt"] = int(msgObject["spt"])

            
            return json.dumps(msgObject)
        else:
            return '{}'
    
    def test_connection(self):
        """
        text connection and check version. on es version depends es-bulk http api. now support ver7 and ver 8. other not tested
        # todo: separate test connecion and version in separate methods. check version once, and check health before send data. 
        Returns:
            tuple: success: bool
        """
        return_value = False
        try:
            # check cluster health
            health_url = f"{self.base_url}/_cluster/health"
            health_response = requests.get(
                health_url,
                auth=self.auth,
                timeout=10,
                verify=self.es_ssl
            )
            
            if health_response.status_code == 200:
                health = health_response.json()
                cluster_status = health.get('status', 'unknown')
                self.logger.info(f"Elasticsearch status: {cluster_status}")
                return_value = True
            else:
                self.logger.error(f"Cannot get cluster status: {health_response.status_code}")
                return False
            
            # check version. we have diffent format between ver 7 and 8
            version_url = f"{self.base_url}/"
            version_response = requests.get(
                version_url,
                auth=self.auth,
                timeout=10,
                verify=self.es_ssl
            )
            
            if version_response.status_code != 200:
                self.logger.error(f"Cannot get Elasticsearch version: {version_response.status_code}")
                return False
            # parse major version from "8.13.1"
            try:
                version_info = version_response.json()
                version_number = version_info.get('version', {}).get('number', '')
                major_version = int(version_number.split('.')[0])
                self.es_major_version = major_version 
                self.logger.info(f"Elasticsearch Name: {version_info.get('cluster_name', 'unknown')}")
                self.logger.debug(f"Elasticsearch version: {version_number} (major: {major_version})")
            except (ValueError, IndexError):
                self.logger.error(f"Cannot parse version: {version_number}")
                major_version = None
            
               
        except Exception as e:
            self.logger.error(f"Cannot connect to Elasticsearch: {e} {self.es_host} ")
            return False
        return return_value
