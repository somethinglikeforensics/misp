from datetime import datetime, timedelta
import logging
logging.basicConfig(
    filename="AlienVaultOTXPulseFeed-{}.log".format(datetime.utcnow().strftime('%Y-%m-%d')),
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

from const import CONST
from OTXv2 import OTXv2, IndicatorTypes
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute

class MispOTXPulseFeed:
    def __init__(self, api_key, lookback_days=None):        
        
        self.misp_conn = ExpandedPyMISP(CONST.MISP_URL, CONST.MISP_KEY, CONST.MISP_VERIFY_CERT)
        self.otx_conn = OTXv2(api_key)
        
        self.search_from_ts = (datetime.now() - timedelta(days=lookback_days)) if lookback_days != None else None
        
        self.list_of_pulse_dicts = self.otx_conn.getall(modified_since=self.search_from_ts.strftime('%Y-%m-%dT%H:%M:%S'))

        for pulse_dict in self.list_of_pulse_dicts:    
            if len(pulse_dict['indicators']) < 1:
                continue
            
            event = self.title_worker(pulse_dict)
            attribute = self.attribute_worker(pulse_dict, event)
            

    def attribute_worker(self, pulse_dict, event):
        attribute_list = list()
        for indicator in pulse_dict['indicators']:            
            attribute = MISPAttribute()
            attribute.value=indicator['indicator']
            attribute.to_ids = True if indicator['is_active'] == 1 else False            
            attribute.comment=pulse_dict['name']          
                        
            try:
                attribute.type = CONST.TYPE_LOOKUP[indicator['type'].upper()]
    
                if attribute.type in CONST.NETWORK_INDICATORS:
                    attribute.category="Network activity"
                elif "HASH" in indicator['type'].upper():
                    attribute.category="Payload delivery"
            
            except KeyError:
                logging.error("This indicator type ({}) is not supported. Please ask to a dev to add this to the CONST lookup dict ;]".format(indicator['type']))
                logging.error("Supported types are {}".format(CONST.TYPE_LOOKUP))

            attribute_list.append(attribute)
        
        return self.misp_conn.add_attribute(event, attribute_list)

    def title_worker(self, pulse_dict):        
        pulse_created = datetime.strptime(pulse_dict['modified'], '%Y-%m-%dT%H:%M:%S.%f')
        # crops main name/title as some pulses include per second timestamps in title, leading to many duplicates
        misp_event_title = "OTX|{}|{}|{}|modified:{}".format(pulse_dict['id'], pulse_dict['author_name'], pulse_dict["name"][:25], pulse_created.strftime('%Y-%m-%d'))            
        
        if self.return_misp_event_from_title(misp_event_title) == None:
            misp_event = self.create_misp_event(misp_event_title)        
            logging.info("New event created from {} and {} tags added".format(pulse_dict['author_name'], self.pulse_tag_worker(pulse_dict, misp_event)))             
            
        else: 
            misp_event = self.return_misp_event_from_title(misp_event_title)            
        
        return misp_event
        
    def create_misp_event(self, misp_event_title):        
        event = MISPEvent()
        event.threat_level_id = "2"
        event.analysis = "2"        
        event.info = misp_event_title
        new_event = self.misp_conn.add_event(event, pythonify=True)
        return new_event

    def return_misp_event_from_title(self, title):        
        evts = self.misp_conn.search(controller="events", eventinfo=title, pythonify=True)        
        return evts[0] if evts else None

    def pulse_tag_worker(self, pulse_dict, misp_event):
        
        tags = ["AlienVaultOTX", "ttsoar_otx_consumer"]
        tlp = "tlp:{}".format(pulse_dict['tlp']) if pulse_dict['tlp'] else None        
        tags.append(tlp) if tlp else None

        for malware in pulse_dict['malware_families']:
           tags.append(malware)
        
        tags.append("{}".format(pulse_dict['adversary']))
        
        for tag in pulse_dict['tags']:
            tags.append(tag)
        
        counter=0  
        for tag in tags:            
            if tag != "":
                self.misp_conn.tag(misp_event['uuid'], tag)
                counter+=1               
        return counter
        

worker = MispOTXPulseFeed(api_key=CONST.OTX_KEY, lookback_days=3)
