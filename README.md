OTX2MISP

AlienVault OTX (https://otx.alienvault.com/) is a free service allowing users to publish indicators of compromise (Ioc) feeds ("pulses").
This script works through your subscribed OTX feeds and generates Misp events based on arbitrary vaules from the pulses' title and author, in an attempt to reduce the number of similar misp events created.

Usage
Edit the const.py with your OTX and Misp instance details
Recommended usage is via crontab schedule
