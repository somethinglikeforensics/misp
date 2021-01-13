## OTX2MISP

AlienVault OTX (https://otx.alienvault.com/) is a free service allowing users to publish indicators of compromise (*Ioc*) feeds as *pulses*.
MISP is an open-source threat intelligence (https://www.misp-project.org/)

This script will pull your subscribed OTX pulses and generate MISP events based on arbitrary vaules from the pulses' title and author (in an attempt to reduce the number of similar misp events created). Indicators from the pulses are then populated on the created MISP events.

### Usage
- Edit the const.py with your OTX and Misp instance details
- Recommended usage is via crontab schedule
- Change the number of days previous to search over when the class instance is called, e.g:

> worker = MispOTXPulseFeed(lookback_days=3)

