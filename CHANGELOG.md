# CHANGELOG.md

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