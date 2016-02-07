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
