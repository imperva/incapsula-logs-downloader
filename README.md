# logs-downloader

----------
**A Python script for downloading log files from Incapsula.**

----------


**Running the script:**

**`python LogsDownloader.py -c path_to_config_folder -l path_to_system_logs_folder -v system_logs_level`**

 - The **-c** and **-l** and **–v** parameters are optional
 - The default value for **path_to_config_folder** is **/etc/incapsula/logs/config**
 - The default value for **path_to_system_logs_folder** is **/var/log/incapsula/logsDownloader/**
 - The default value for **system_logs_level** is **info**
 - The **path_to_config_folder** is the folder where the settings file (**Settings.Config**) is stored
 - The **path_to_system_logs_folder** is the folder where the script output log file is stored (this does not refer to your Incapsula logs)
 - The **system_logs_level** configuration parameter holds the logging level for the script output log. The supported levels are **info**, **debug** and **error**
 - You can run **`LogsDownloader.py -h`** to get help

**Preparations for using the script:**

 - Create a local folder for holding the script configuration, this will be referred as **path_to_config_folder**
 - Create a subfolder named **keys** under the **path_to_config_folder** folder 
 - In the keys subfolder, create a subfolder with a single digit name. This digit should specify whether this is the first encryption key uploaded (1), the second (2) or so on
 - Inside that folder, save the private key with the name **Private.key**
 - For example, **/etc/incapsula/logs/config/keys/1/Private.key**

**Dependencies:**

The script has two dependencies that may require additional installation modules, according to the operating system that is used:

 - **M2Crypto**
 - **loggerglue**

Both of these can be downloaded using apt-get, pip or any other installer, depending on the operating system in use.

**Running the script as a service on Linux systems:** 

 - You can run the script as a service on Linux systems by using the configuration file - **linux_service_configuration/incapsulaLogs.conf**
 -  You should modify the following parameters in the configuration file according to your environment: 
	 1. **`$USER$`** - The user that will execute the script
	 2. **`$GROUP$`** - The group name that will execute the script
	 3. **`$PYTHON_SCRIPT$`** - The path to the **`LogsDownloader.py`** file, followed by the parameters for execution of the script
 - On your system, copy the **incapsulaLogs.conf** file and place it under the **/etc/init/** directory
 - Run **`sudo initctl reload-configuration`** 
 - Run **`sudo ln -s /etc/init/incapsulaLogs.conf /etc/init.d/incapsulaLogs`**
 - Execute **`sudo service incapsulaLogs start`** 
 - You can use **`start/stop/status`** as any other Linux service
