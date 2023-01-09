import configparser
import os

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
            config_parser = configparser.ConfigParser()
            config_parser.read(config_file)
            config = Config(self.config_path, self.logger)

            # Check for environment variables first, then load config values. Backwards compatibility with non-docker deployments
            config.API_ID = os.environ.get('IMPERVA_API_ID', config_parser.get("SETTINGS", "APIID"))
            config.API_KEY = os.environ.get('IMPERVA_API_KEY', config_parser.get("SETTINGS", "APIKEY"))
            config.PROCESS_DIR = os.environ.get('IMPERVA_LOG_DIRECTORY',
                os.path.join(config_parser.get("SETTINGS", "PROCESS_DIR"), ""))
            config.BASE_URL = os.environ.get('IMPERVA_API_URL',
                os.path.join(config_parser.get("SETTINGS", "BASEURL"), ""))
            config.SAVE_LOCALLY = os.environ.get('IMPERVA_SAVE_LOCALLY', config_parser.get("SETTINGS", "SAVE_LOCALLY"))
            config.USE_PROXY = os.environ.get('IMPERVA_USE_PROXY', config_parser.get("SETTINGS", "USEPROXY"))
            config.PROXY_SERVER = os.environ.get('IMPERVA_PROXY_SERVER', config_parser.get("SETTINGS", "PROXYSERVER"))
            config.SYSLOG_ENABLE = os.environ.get('IMPERVA_SYSLOG_ENABLE',
                config_parser.get('SETTINGS', 'SYSLOG_ENABLE'))
            config.SYSLOG_ADDRESS = os.environ.get('IMPERVA_SYSLOG_ADDRESS',
                config_parser.get('SETTINGS', 'SYSLOG_ADDRESS'))
            config.SYSLOG_PORT = os.environ.get('IMPERVA_SYSLOG_PORT', config_parser.get('SETTINGS', 'SYSLOG_PORT'))
            config.SYSLOG_PROTO = os.environ.get('IMPERVA_SYSLOG_PROTO', config_parser.get('SETTINGS', 'SYSLOG_PROTO'))
            config.USE_CUSTOM_CA_FILE = os.environ.get('IMPERVA_USE_CUSTOM_CA_FILE',
                config_parser.get('SETTINGS', 'USE_CUSTOM_CA_FILE'))
            config.CUSTOM_CA_FILE = os.environ.get('IMPERVA_CUSTOM_CA_FILE',
                config_parser.get('SETTINGS', 'SPLUNK_HEC'))
            config.SPLUNK_HEC = os.environ.get('IMPERVA_SPLUNK_HEC',
                config_parser.get('SETTINGS', 'SPLUNK_HEC'))
            config.SPLUNK_HEC_IP = os.environ.get('IMPERVA_SPLUNK_HEC_IP',
                config_parser.get('SETTINGS', 'SPLUNK_HEC_IP'))
            config.SPLUNK_HEC_PORT = os.environ.get('IMPERVA_SPLUNK_HEC_PORT',
                config_parser.get('SETTINGS', 'SPLUNK_HEC_PORT'))
            config.SPLUNK_HEC_TOKEN = os.environ.get('IMPERVA_SPLUNK_HEC_TOKEN',
                config_parser.get('SETTINGS', 'SPLUNK_HEC_TOKEN'))
            return config
        else:
            self.logger.error("Could Not find configuration file %s", config_file)
            raise Exception("Could Not find configuration file")