FROM python:3.9

# Copy our script and make it executable
COPY ./script/* /usr/local/bin/
RUN chmod 755 /usr/local/bin/LogsDownloader.py

# We need SWIG as well
RUN apt-get update
RUN apt-get install -y swig openssl python3-pip build-essential python3-dev libssl-dev git

# Copy requirements.txt and install with pip
COPY ./script/requirements.txt /
RUN python3 -m pip install -r /requirements.txt

# Copy our settings
COPY ./config/Settings.Config.template /etc/incapsula/logs/config/Settings.Config

# Run our script
CMD "/usr/local/bin/LogsDownloader.py"