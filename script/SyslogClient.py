import logging
import datetime
import socket

FACILITY = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

LEVEL = {
    'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

"""

Syslog - For sending TCP Syslog messages via socket class

"""


class SyslogClient:
    def __init__(self, host, port, socket_type, logger):
        self.host = host
        self.port = port
        self.socket_type = socket.SOCK_STREAM if socket_type == "TCP" else socket.SOCK_DGRAM
        self.logger = logger

    def send(self, message):
        """
        Send syslog packet to given host and port.
        """
        logging.debug("Send to Host={} on Port={}".format(self.host, self.port))
        sock = socket.socket(socket.AF_INET, self.socket_type)
        sock.connect((self.host, int(self.port)))
        priority = "<{}>".format(LEVEL['info'] + FACILITY['daemon'] * 8)

        try:
            timestamp = self.get_time(message)
        except ValueError:
            self.logger.error("Error converting epoch time.")
            timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")

        try:
            hostname = self.get_hostname(message)
        except ValueError:
            self.logger.error("Error getting hostname.")
            hostname = "imperva.com"

        application = "cwaf"
        data = "{} {} {} {} {}".format(priority, timestamp, hostname, application, message)
        try:
            sock.send(bytes(data, 'utf-8'))
            return "OK"
        except OSError as e:
            self.logger.error(e)
            sock.close()
            return None
        finally:
            sock.close()

    @staticmethod
    def get_time(message):
        if message.startswith("CEF"):
            epoch = int(str(message.split("start=")[1]).split(" ")[0]) / 1000
            timestamp = datetime.datetime.fromtimestamp(int(epoch)).strftime("%b %d %H:%M:%S") or \
                        datetime.datetime.now().strftime("%b %d %H:%M:%S")
        elif message.startswith("LEEF"):
            epoch = int(str(message.split("start=")[1]).split("\t")[0]) / 1000
            timestamp = datetime.datetime.fromtimestamp(int(epoch)).strftime("%b %d %H:%M:%S") or \
                        datetime.datetime.now().strftime("%b %d %H:%M:%S")
        return timestamp

    @staticmethod
    def get_hostname(message):
        if message.startswith("CEF"):
            hostname = str(message.split("sourceServiceName=")[1]).split(" ")[0] or "imperva.com"
        elif message.startswith("LEEF"):
            hostname = str(message.split("sourceServiceName=")[1]).split("\t")[0] or "imperva.com"
        return hostname
