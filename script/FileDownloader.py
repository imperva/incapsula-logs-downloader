import urllib3.exceptions
import traceback

"""

FileDownloader - A class for downloading files

"""


class FileDownloader:

    def __init__(self, config, logger, timeout=20):
        self.config = config
        self.logger = logger

        # https://github.com/imperva/incapsula-logs-downloader/pull/7
        if self.config.USE_PROXY == "YES" and self.config.USE_CUSTOM_CA_FILE == "YES":
            self.logger.info("Using proxy %s" % self.config.PROXY_SERVER)
            self.https = urllib3.ProxyManager(self.config.PROXY_SERVER, ca_certs=self.config.CUSTOM_CA_FILE,
                                         cert_reqs='CERT_REQUIRED', timeout=timeout)
        elif self.config.USE_PROXY == "YES" and self.config.USE_CUSTOM_CA_FILE == "NO":
            self.logger.info("Using proxy %s" % self.config.PROXY_SERVER)
            self.https = urllib3.ProxyManager(self.config.PROXY_SERVER, cert_reqs='CERT_REQUIRED', timeout=timeout)
        elif self.config.USE_PROXY == "NO" and self.config.USE_CUSTOM_CA_FILE == "YES":
            self.https = urllib3.PoolManager(ca_certs=self.config.CUSTOM_CA_FILE, cert_reqs='CERT_REQUIRED', timeout=timeout)
        else:  # no proxy and no custom CA file
            self.https = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', timeout=timeout)

    """
    A method for getting a destination URL file content
    """

    def request_file_content(self, url):
        # default value
        global response
        response_content = ""

        try:
            # Download the file
            auth_header = urllib3.make_headers(basic_auth='%s:%s' % (self.config.API_ID, self.config.API_KEY))
            response = self.https.request('GET', url, headers=auth_header)

            # if we get a 200 OK response
            if response.status == 200:
                self.logger.info("Downloaded %s" % url)
                # read the response content
                response_content = response.data
            # if we get another response code
            elif response.status == 404:
                self.logger.warning("Could not find file %s. Response code is %s", url, response.status)
                response.close()
            elif response.status == 401:
                self.logger.error("Authorization error - Failed to download file %s. Response code is %s", url,
                                  response.status)
                response.close()
                raise Exception("Authorization error")
            elif response.status == 429:
                self.logger.error("Rate limit exceeded - Failed to download file %s. Response code is %s", url,
                                  response.status)
                response.close()
                raise Exception("Rate limit error")
            else:
                self.logger.error("Failed to download file %s. Response code is %s.", url, response.status)
                response.close()
            # close the response
            response.close()
            # return the content string
            return response_content

        except urllib3.exceptions.HTTPError as e:
            self.logger.exception(e)
            raise Exception("Connection error")
        # unexpected exception occurred
        except Exception as e:
            self.logger.exception(e)
            raise Exception("Connection error")
        finally:
            response.close()
