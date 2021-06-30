# Imperva Connector

> A Python script for downloading log files from Imperva CloudWAF

- [CHANGELOG](https://github.com/imperva/incapsula-logs-downloader/blob/master/CHANGELOG.md)  
- [DEPENDENCIES](#dependencies)
- [GETTING STARTED](#getting-started)  
- [EXECUTING THE SCRIPT](#executing-the-script)
- [RUNNING THE SCRIPT AS A SERVICE](#running-the-script-as-a-service)
	- [SysVinit](#sysvinit)
- [DOCKER](#docker)  
	- [Configuration](#configuration)  
	- [Encrypted Logs](#encrypted-logs)

## Dependencies

> This script requires Python 3

The script has the following pythondependencies that may require additional installation modules, according to the operating system that is used. 

- **pycrypto**
- **M2Crypto**

A requirements.txt file is included in the script directory, so that the following can be used to install requirements and dependencies:

```
pip install -r requirements.txt
```

## Getting Started

- Create a local folder for holding the script configuration, this will be referred as **path_to_config_folder**
	- copy the Settings.Config.example file to this folder as Settings.Config.
	- Create a subfolder named **keys** under the **path_to_config_folder** folder 
	- In the keys subfolder, create a subfolder with a single digit name. This digit should specify whether this is the first encryption key uploaded (1), the second (2) or so on
	- Inside that folder, save the private key with the name **Private.key**:

## Executing The Script

An example for calling the script is below:

```
python LogsDownloader.py \
  -c path_to_config_folder \
  -l path_to_system_logs_folder \
  -v system_logs_level
```

- The **-c** and **-l** and **–v** parameters are optional
- The default value for **path_to_config_folder** is **/etc/incapsula/logs/config**
- The default value for **path_to_system_logs_folder** is **/var/log/incapsula/logsDownloader/**
- The default value for **system_logs_level** is **info**
- The **path_to_system_logs_folder** is the folder where the script output log file is stored. **NOTE**: This is for the script output only. The location to store the CloudWAF logs is defined in the Settings.Config file or IMPERVA_LOG_DIRECTORY environment variable.
- The **system_logs_level** configuration parameter holds the logging level for the script output log. The supported levels are **info**, **debug** and **error**
- You can run **`LogsDownloader.py -h`** to get help

## Running The Script As A Service

### SysVinit
You can run the script as a service on Linux systems by using the configuration file - **linux_service_configuration/incapsulaLogs.conf**

You should modify the following parameters in the configuration file according to your environment:
1. **`$USER$`** - The user that will execute the script
2. **`$GROUP$`** - The group name that will execute the script
3. **`$PYTHON_SCRIPT$`** - The path to the **`LogsDownloader.py`** file, followed by the parameters for execution of the script

On your system, copy the **incapsulaLogs.conf** file and place it under the **/etc/init/** directory
```
sudo cp incapsulaLogs.conf /etc/init/incapsulaLogs.conf
sudo initctl reload-configuration
sudo ln -s /etc/init/incapsulaLogs.conf /etc/init.d/incapsulaLogs
sudo service incapsulaLogs start
```

You can use `start/stop/status` as any other Linux service

## Docker

A dockerfile is provided to build your own image locally. At this time, a dockerhub image is not available.

### Configuration

The connector script will look for the following environment variables, and fall back to the configuration file if the environment variable is not set:

	IMPERVA_API_KEY (required)  
	IMPERVA_API_ID (required)  
	IMPERVA_API_URL (required)  
	IMPERVA_LOG_DIRECTORY (optional)  
	IMPERVA_SAVE_LOCALLY (optional)  
	IMPERVA_USE_PROXY (optional)  
	IMPERVA_PROXY_SERVER (optional)  
	IMPERVA_SYSLOG_ENABLE (optional)  
	IMPERVA_SYSLOG_ADDRESS (optional)  
	IMPERVA_SYSLOG_PORT (optional)  
	IMPERVA_SYSLOG_PROTO (optional)  
	IMPERVA_USE_CUSTOM_CA_FILE (optional)  
	IMPERVA_CUSTOM_CA_FILE (optional, see note below)

> Note - In order to use a custom CA file, you will need to either build a docker image with the file embedded, or mount a persistent data volume to the image and provide the full path to the file as this variable value.

### Encrypted Logs
	
The recommended method would be to mount a persistent data volume at /etc/incapsula/logs/config/keys that contains numbered subfolders with key files as detailed in [Preparations for using the script](#preparations-for-using-the-script).

You can also use the dockerfile in this repo to build the image with your keys baked in.