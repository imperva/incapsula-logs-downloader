# CHANGELOG.md

## 2.4.1
Features:
- added support for JSON content files

## 2.4.0
Features:
 - removing the download process from the main thread with async pools
 - added an incoming directory for initial download, now we download to incoming, move to process and finally to archive
 - LastKnownDownloadedFileId.txt has been removed and no longer used
## 2.3.0
Features:
 - converted syslog_handler to native sockets lb
 - converted splunk_handler to native requests lib
 - split log download and log upload/send threads
 - added processed logs archiver

## 2.2.0
Features:
  - enable syslog forwarding over TCP (removed loggerglue dependency)

## 2.1.0

Features:
  - update to urllib3 for working proxies

## 2.0.0

Features:
  - convert to Python3
  - update config parsing to pull environment variables first, and fall back to config file if environment variable doesn't exist
  - added requirements.txt for python pip dependencies