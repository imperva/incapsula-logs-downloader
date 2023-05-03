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

            # Check for environment variables first, then load config values.
            # Backwards compatibility with non-docker deployments
            config.API_ID = os.environ.get('IMPERVA_API_ID', config_parser.get("SETTINGS", "IMPERVA_API_ID"))
            config.API_KEY = os.environ.get('IMPERVA_API_KEY', config_parser.get("SETTINGS", "IMPERVA_API_KEY"))
            config.INCOMING_DIR = os.environ.get('IMPERVA_INCOMING_DIR',
                                                 os.path.join(config_parser.get('SETTINGS', 'IMPERVA_INCOMING_DIR'), "")
                                                 or os.path.join(os.getcwd(), "incoming"))
            config.PROCESS_DIR = os.environ.get('IMPERVA_PROCESS_DIR',
                                                os.path.join(config_parser.get("SETTINGS", "IMPERVA_PROCESS_DIR"), "")
                                                or os.path.join(os.getcwd(), "process"))
            config.ARCHIVE_DIR = os.environ.get('IMPERVA_ARCHIVE_DIR',
                                                os.path.join(config_parser.get('SETTINGS', 'IMPERVA_ARCHIVE_DIR'), "")
                                                or False) # os.path.join(os.getcwd(), "archive")
            config.BASE_URL = os.environ.get('IMPERVA_API_URL',
                config_parser.get("SETTINGS", "IMPERVA_API_URL"))
            config.USE_PROXY = os.environ.get('IMPERVA_USE_PROXY', config_parser.get("SETTINGS", "IMPERVA_USE_PROXY") or "NO")
            config.PROXY_SERVER = os.environ.get('IMPERVA_PROXY_SERVER', config_parser.get("SETTINGS", "IMPERVA_PROXY_SERVER"))
            config.USE_CUSTOM_CA_FILE = os.environ.get('IMPERVA_USE_CUSTOM_CA_FILE',
                config_parser.get('SETTINGS', 'IMPERVA_USE_CUSTOM_CA_FILE') or "NO")
            config.CUSTOM_CA_FILE = os.environ.get('IMPERVA_CUSTOM_CA_FILE',
                config_parser.get('SETTINGS', 'IMPERVA_CUSTOM_CA_FILE'))
            config.SYSLOG_ENABLE = os.environ.get('IMPERVA_SYSLOG_ENABLE',
                config_parser.get('SETTINGS', 'IMPERVA_SYSLOG_ENABLE') or "NO")
            config.SYSLOG_ADDRESS = os.environ.get('IMPERVA_SYSLOG_ADDRESS',
                config_parser.get('SETTINGS', 'IMPERVA_SYSLOG_ADDRESS'))
            config.SYSLOG_PORT = os.environ.get('IMPERVA_SYSLOG_PORT', config_parser.get('SETTINGS', 'IMPERVA_SYSLOG_PORT'))
            config.SYSLOG_PROTO = os.environ.get('IMPERVA_SYSLOG_PROTO', config_parser.get('SETTINGS', 'IMPERVA_SYSLOG_PROTO') or "UDP")
            config.SPLUNK_HEC = os.environ.get('IMPERVA_SPLUNK_HEC',
                config_parser.get('SETTINGS', 'IMPERVA_SPLUNK_HEC') or "NO")
            config.SPLUNK_HEC_IP = os.environ.get('IMPERVA_SPLUNK_HEC_IP',
                config_parser.get('SETTINGS', 'IMPERVA_SPLUNK_HEC_IP'))
            config.SPLUNK_HEC_PORT = os.environ.get('IMPERVA_SPLUNK_HEC_PORT',
                config_parser.get('SETTINGS', 'IMPERVA_SPLUNK_HEC_PORT'))
            config.SPLUNK_HEC_TOKEN = os.environ.get('IMPERVA_SPLUNK_HEC_TOKEN',
                config_parser.get('SETTINGS', 'IMPERVA_SPLUNK_HEC_TOKEN'))
            config.SPLUNK_HEC_SRC_HOSTNAME = os.environ.get('IMPERVA_SPLUNK_HEC_SRC_HOSTNAME',
                config_parser.get('SETTINGS', 'IMPERVA_SPLUNK_HEC_SRC_HOSTNAME'))
            config.SPLUNK_HEC_INDEX = os.environ.get('IMPERVA_SPLUNK_HEC_INDEX',
                config_parser.get('SETTINGS', 'IMPERVA_SPLUNK_HEC_INDEX') or "imperva")
            config.SPLUNK_HEC_SOURCE = os.environ.get('IMPERVA_SPLUNK_HEC_SOURCE',
                config_parser.get('SETTINGS', 'IMPERVA_SPLUNK_HEC_SOURCE') or "log_downloader")
            config.SPLUNK_HEC_SOURCETYPE = os.environ.get('IMPERVA_SPLUNK_HEC_SOURCETYPE',
                config_parser.get('SETTINGS', 'IMPERVA_SPLUNK_HEC_SOURCETYPE') or "imperva:cef")
            config.ENABLE_TRACING = os.environ.get('IMPERVA_ENABLE_TRACING',
                config_parser.get('SETTINGS', 'IMPERVA_ENABLE_TRACING'))
            config.OTLP_ENDPOINT = os.environ.get('IMPERVA_OTLP_ENDPOINT',
                config_parser.get('SETTINGS', 'IMPERVA_OTLP_ENDPOINT'))
            return config
        else:
            self.logger.error("Could Not find configuration file %s", config_file)
            raise Exception("Could Not find configuration file")