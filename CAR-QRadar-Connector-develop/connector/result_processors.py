import json
import hashlib
import copy
import random
import re
import string

from car_framework.context import context

def hash_string(string):
    string=str(string).encode('utf-8')
    return int(hashlib.sha256(string).hexdigest()[:16], 16)-2**63

class ResultProcessor(object):

    def __init__(self, config, data_handler) -> None:
        super().__init__()
        self.config = config
        self.data_handler = data_handler
        self.item_count = 0
        self.edge_count = {}
        self.other_collections_count = {}
        
        # Storage for building edge/collectioon items up in memory 
        self.collection_dict = {}
        self.edge_dict = {}

        self.max_in_memory_size = max( 10 * context().args.export_data_page_size, 20000)

    def add_edge(self, name, edge_data):

        self.edge_dict[name].append(edge_data)

        if len(self.edge_dict[name]) >= self.max_in_memory_size:
            self.data_handler.handle_edge_list(name, self.edge_dict[name])

    def add_collection_item(self, name, collection_data):

        self.collection_dict[name][0].append(collection_data)

        if len(self.collection_dict[name][0]) >= self.max_in_memory_size:
            self.data_handler.handle_collection_list(name, self.collection_dict[name][0], self.collection_dict[name][1])

    def handle_remaining_collection_and_edge_items(self):

        for k, v in self.edge_dict.items():
            if len(v) > 0:
                  self.data_handler.handle_edge_list(k, v)

        for k, v in self.collection_dict.items():
            if len(v[0]) > 0:
                self.data_handler.handle_collection_list(k, v[0], v[1])


    def delete(self, name, ids):

        context().car_service.delete(name, ids)


    def create_collection_entry(self, entry_item):

        entry = {}

        key_map = self.config['api_key_map'].copy()
        external_refs = key_map.pop("EXT_REF", None)

        for k, v in key_map.items():

            # Remove None items
            if entry_item[k]:
                entry[v] = entry_item[k]

        # dictionary
        xrefs = {}

        # list
        properties = []
        if external_refs:

            for k, v in external_refs.items():

                # Don't send properties with None values
                if entry_item.get(k):
                    property_vuln = {}
                    property_vuln['extref_typename'] = str(v)
                    property_vuln['extref_value'] = str(entry_item[k])
                    properties.append(property_vuln)

            # add list to first dict
            xrefs['properties'] = properties
            # add first dict to second dict
            entry['xref_properties'] = xrefs

        return entry

    def get_query_from_file(self, file):

        file_dir = context().app_dir + "/config/queries/"+file

    
        #handle incremental queries
        if "inc.json" in file or "del.json" in file:
            with open(file_dir) as f:
                
                #manage asset queries by search using the id of assets which have a change
                if "query-asset-props-inc.json" in file or "query-asset-custom-props-inc.json" in file:
                    asset_ids = ['0']
                    for item in self.assets:
                        asset_ids.append(item)
                    assets_string = ','.join(str('"' + x + '"') for x in asset_ids)
                    return json.loads(f.read() % {"asset_ids": assets_string[1:-1]})     
                
                #manage all other incremental queries by getting the timestamp since last ran
                else:
                    car_model_state_id = str(context().car_service.get_model_state_id())
                    return json.loads(f.read() % {"date_timestamp": (int(car_model_state_id[:10])*1000)})
        
        else:
            with open(file_dir) as fh:
                return json.load(fh)

    def complete_collection(self):

        # Not required for every collection
        pass

    def get_summary(self):

        collection = self.config['collection']

        summary = f"Retrieving {collection.title()}(s) finished. Got: {self.item_count} {collection.title()}(s)"

        for k, v in self.other_collections_count.items():

            summary += f", {v} {k.title()}(s)"

        for k, v in self.edge_count.items():

            summary += f", {v} {k} edges"

        return summary

    def run(self):

        collection = self.config['collection']
        context().logger.info("Retrieving {}(s) from QRadar".format(collection.title()))
        
        # HTTPSConnectionPool was throwing SSL errors when the same QRadarApi instance was being used by all child threads
        qradar_api = copy.deepcopy(context().asset_server)

        for api_call in self.config['apis']:

            query_file = api_call['query_file']

            if query_file == 'query-vulnerability.json' and context().args.vuln_id_available:
                query_file = 'query-vulnerability-with-vuln-id.json'

            if query_file == 'query-port.json' and context().args.incremental_supported:
                query_file = 'query-port-with-id.json'

            if query_file == 'query-vulnerability-ip.json' and context().args.incremental_supported:
                query_file = 'query-vulnerability-ip-with-id.json'

            query = self.get_query_from_file(query_file)                

            page_limit = api_call.get('page_limit', 100000)
            callback = getattr(self, api_call['handler'])

            qradar_api.run_dynamic_search(
                query, page_limit=page_limit, callback=callback)

        self.complete_collection()

        context().logger.info(self.get_summary())

    def run_uba(self):

        context().logger.info("Retrieving UBA data from QRadar")

        qradar_api = copy.deepcopy(context().asset_server)

        callback = getattr(self, 'process_uba_values')

        qradar_api.run_uba_query(callback=callback)



class VulnerabilityResultProcessor(ResultProcessor):

    def __init__(self, config, data_handler) -> None:
        super().__init__(config, data_handler)
        self.vuln_cve_ids = {}
        self.id_map = {}
        self.duplicates = {}
        self.edge_count['ipaddress_vulnerability'] = 0
        self.edge_count['asset_vulnerability'] = 0

        self.edge_dict['ipaddress_vulnerability'] = []
        self.edge_dict['asset_vulnerability'] = []

        self.collection_dict['vulnerability'] = ([], 'external_id')

        # QRadar has eaxactly the same vulns but with a different vuln id. Leave them out untl we get viln ids in the future.
        self.asset_vuln_id_record = {} 

    def process_vuln_cve_ids(self, response_json):

        context().logger.debug(
            f"process_vuln_cve_ids: Processing a batch of {len(response_json)} cve ids")

        for item in response_json:

            cve_id = item.get("VULNINSTANCE_CVE_ID")
            vuln_instance_id = item.get("VULNINSTANCE_ID")

            if cve_id and vuln_instance_id:

                if not self.vuln_cve_ids.get(vuln_instance_id):
                    self.vuln_cve_ids[vuln_instance_id] = f"CVE-{cve_id}"
                else:

                    if cve_id not in self.vuln_cve_ids[vuln_instance_id]: self.vuln_cve_ids[vuln_instance_id] += f",CVE-{cve_id}"

    def process_vuln_ips(self, response_json):

        context().logger.debug(
            f"process_vuln_ips: Processing a batch of {len(response_json)} vuln IPs")

        name = "ipaddress_vulnerability"

        for item in response_json:

            ip = item.get("VULNINSTANCE_IPADDRESS")
            asset_id = item.get("VULNINSTANCE_ASSET_ID")
            vuln_instance_id = str(item.get("VULNINSTANCE_ID"))
            vuln_id = self.id_map.get(vuln_instance_id)
            vuln_instance_ipaddress_id = item.get("VULNINSTANCE_IPADDRESS_ID")

            if ip and vuln_instance_id and vuln_id:

                if context().args.incremental_supported:
                    edge_id = vuln_instance_ipaddress_id
                else:
                    edge_id = ip + vuln_instance_id

                self.add_edge(name, {
                    '_from': "ipaddress/" + ip,
                    '_to_external_id': vuln_id,
                    "external_id": edge_id})

                self.edge_count[name] += 1

        self.handle_remaining_collection_and_edge_items()

    def process_asset_vuln(self, asset_id, vuln_id, vuln_instance_id):

        if asset_id and vuln_id and vuln_instance_id:

            k = hash(str(asset_id) + vuln_id)

            if k in self.asset_vuln_id_record:
                return
            else:
                self.asset_vuln_id_record[k]=True

            self.add_edge('asset_vulnerability', {
                '_from_external_id': asset_id,
                '_to_external_id': vuln_id,
                "external_id": vuln_instance_id})

            self.edge_count['asset_vulnerability'] += 1

    def get_id_string(self, vuln_instance):

        ret_string  = ''
        for k, v in vuln_instance.items():
            if k != "VULNINSTANCE_ID" and k != "VULNINSTANCE_ASSET_ID" and v:
                ret_string += v
        return ret_string


    def process_vuln_instances(self, response_json):

        context().logger.debug(
            f"process_vuln_instances: Processing a batch of {len(response_json)} vuln instances")

        collection_name = self.config['collection'] # Vulnerability

        while len(response_json) > 0:

            vuln_instance = response_json.pop()
            vuln_name = vuln_instance.get("VULNINSTANCE_NAME")

            if not vuln_name:
                break

            vuln_id = vuln_instance.get("VULNINSTANCE_VULN_ID") if context().args.vuln_id_available else str(hash_string(self.get_id_string(vuln_instance)))
            vuln_instance_id = str(vuln_instance['VULNINSTANCE_ID'])

            self.id_map[vuln_instance_id] = vuln_id


            # asset_vulnerability edge
            asset_id = vuln_instance.get("VULNINSTANCE_ASSET_ID")
            self.process_asset_vuln(asset_id, vuln_id, vuln_instance_id)

            if vuln_id in self.duplicates: continue
            
            
            vuln_instance['VULN_ID'] = vuln_id
            self.duplicates[vuln_id] = True

            vuln = self.create_collection_entry(vuln_instance)

            cve_ids = self.vuln_cve_ids.get(vuln_instance_id)
            if cve_ids:
                vuln['external_reference'] = cve_ids
            
            # convert values for CAR schema validation
            vuln['base_score'] = float(vuln_instance.get("VULNINSTANCE_CVSS_BASE_SCORE"))
            vuln['published_on'] = int(vuln_instance.get("VULNINSTANCE_PUBLISH_DATE"))

            self.add_collection_item(collection_name, vuln)
            self.item_count += 1


        self.handle_remaining_collection_and_edge_items()


    def update_vuln_ips(self, response_json):
            
        vuln_ip_ids = []
        for item in response_json:
            vuln_ip_ids.append(item['VULNINSTANCE_IPADDRESS_ID'])

        self.delete('ipaddress_vulnerability', vuln_ip_ids)

        self.process_vuln_ips(response_json)

    def delete_vuln_ips(self, response_json):

        vuln_ip_ids = []
        for item in response_json:
            vuln_ip_ids.append(item['VULNASSET_TRACKING_DELETED_ID'])
            self.edge_count['ipaddress_vulnerability'] += 1

        self.delete('ipaddress_vulnerability', vuln_ip_ids)


    def update_vuln_instances(self, response_json):

        vuln_instance_ids =[]
        for item in response_json:
            vuln_instance_ids.append(item['VULNINSTANCE_ID'])

        self.delete('asset_vulnerability', vuln_instance_ids)

        self.process_vuln_instances(response_json)

    def delete_vuln_instances(self, response_json):
        #vulnerabilities are shared so this only deletes the edge for the corresponsing vuln instance
        vuln_instance_ids = []
        for item in response_json:
            vuln_instance_ids.append(item['VULNASSET_TRACKING_DELETED_ID'])
            self.edge_count['asset_vulnerability'] += 1

        self.delete('asset_vulnerability', vuln_instance_ids)
        


class IpaddressResultProcessor(ResultProcessor):

    def __init__(self, config, data_handler) -> None:
        super().__init__(config, data_handler)
        self.ip_addresses = {}
        self.edge_count['asset_ipaddress'] = 0
        self.edge_dict['asset_ipaddress'] = []
        self.collection_dict['ipaddress'] = ([], '_key')

    def process_ip_addresses(self, response_json):

        edge_name = "asset_ipaddress"
        collection_name = self.config['collection'] # ipaddress

        for item in response_json:

            ip = item['ASSET_IPADDRESS']
            if context().args.incremental_supported:
                ip_address_id = item['ASSET_IPADDRESS_ID']

                self.add_edge(edge_name, {
                    '_from_external_id': item['ASSET_ID'],
                    '_to': "ipaddress/" + ip,
                    "external_id": ip_address_id})
            else:
                self.add_edge(edge_name, {
                    '_from_external_id': item['ASSET_ID'],
                    '_to': "ipaddress/" + ip})
            self.edge_count[edge_name] += 1

            if ip in self.ip_addresses:
                continue
            else:
                self.ip_addresses[ip] = True
                self.add_collection_item(collection_name,{'_key': ip})
                self.item_count += 1

        self.handle_remaining_collection_and_edge_items()

    def update_ip_addresses(self, response_json):

        ip_address_ids = []
        for item in response_json:
            ip_address_ids.append(item['ASSET_IPADDRESS_ID'])

        self.delete('asset_ipaddress', ip_address_ids)

        self.process_ip_addresses(response_json)

    def delete_ip_addresses(self, response_json):
        
        ip_address_ids = []
        for item in response_json:
            ip_address_ids.append(item['VULNASSET_TRACKING_DELETED_ID'])
            self.item_count += 1

        self.delete('asset_ipaddress', ip_address_ids)


class MacaddressResultProcessor(ResultProcessor):

    def __init__(self, config, data_handler) -> None:
        super().__init__(config, data_handler)
        self.mac_addresses = {}
        self.edge_count['ipaddress_macaddress'] = 0
        self.edge_count['asset_macaddress'] = 0
        self.edge_dict['ipaddress_macaddress'] = []
        self.edge_dict['asset_macaddress'] = []
        self.collection_dict['macaddress'] = ([], '_key')

    def process_mac_addresses(self, response_json):

        collection_name  = self.config['collection'] # macaddress
        ip_mac = "ipaddress_macaddress"
        asset_mac = "asset_macaddress"


        for item in response_json:

            mac = item['ASSET_MACADDRESS']
            interface = item['ASSET_INTERFACE_ID']
            asset_id = item['ASSET_ID']
            ip = item['ASSET_IPADDRESS']
            ip_address_id = item['ASSET_IPADDRESS_ID']
        
            if not mac:
                continue

            # Validate Mac address
            mac_list = self.validate_mac_addresses(mac)
            
            for mac in mac_list:
                if ip:
                    self.add_edge(ip_mac, {
                        '_from': 'ipaddress/' + ip,
                        '_to': 'macaddress/' + mac,
                        'external_id': ip_address_id})
                    self.edge_count['ipaddress_macaddress'] += 1

                # only do the duplicate check if the list has entries 
                if self.edge_count['asset_macaddress'] > 1:
                    # check for the existence of the macaddress in the list
                    reportMac = 'macaddress/' + mac
                    duplicateCheck = False
                    for record in self.edge_dict[asset_mac]:
                        if record['_to'] == reportMac:
                            duplicateCheck = True
                    # add a new record only if macaddress not already present
                    if not duplicateCheck:
                        self.add_edge(asset_mac, {
                            '_from_external_id': asset_id,
                            '_to': 'macaddress/' + mac,
                            "external_id": interface + asset_id})
                        self.edge_count['asset_macaddress'] += 1
                else:
                    # add first record to list
                    self.add_edge(asset_mac, {
                            '_from_external_id': asset_id,
                            '_to': 'macaddress/' + mac,
                            "external_id": interface + asset_id})
                    self.edge_count['asset_macaddress'] += 1

                if mac in self.mac_addresses and self.mac_addresses[mac] == interface:
                    continue
                else:
                    self.mac_addresses[mac] = interface
                    self.add_collection_item(collection_name,{'_key': mac, 'interface': interface})
                    self.item_count += 1

        self.handle_remaining_collection_and_edge_items()

    def update_mac_addresses(self, response_json):

        interface_ids =[]
        ip_address_ids =[]
        for item in response_json:

            interface_ids.append(item['ASSET_INTERFACE_ID'])
            ip_address_ids.append(item['ASSET_IPADDRESS_ID'])

        self.delete('asset_macaddress', interface_ids)
        self.delete('ipaddress_macaddress', ip_address_ids)

        self.process_mac_addresses(response_json)

    def delete_mac_addresses(self, response_json):
        
        asset_mac_ids = []
        ip_mac_ids = []

        for item in response_json:

            if 'interface' in item['VULNASSET_TRACKING_TABLE_NAME']:
                asset_mac_ids.append(item['VULNASSET_TRACKING_DELETED_ID'])
                self.edge_count['asset_macaddress'] += 1
            else:
                ip_mac_ids.append(item['VULNASSET_TRACKING_DELETED_ID'])
                self.edge_count['ipaddress_macaddress'] += 1

        self.delete('asset_macaddress', asset_mac_ids)
        self.delete('ipaddress_macaddress', ip_mac_ids)

    def validate_mac_addresses(self, mac):

        # Log the full MAC Address string if it is invalid
        if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
                context().logger.warning(f"{mac} is not a valid MAC address. Will attempt to extract any valid MAC addresses from {mac}")    
        # Finds all pairs of hexadecimal numbers sparated by either 5 : or - and puts it into a list 
        mac_list = re.findall("(?:[0-9a-fA-F]:?){12}|(?:[0-9a-fA-F]-?){12}", mac)
        # Checks each mac address found in the list to find if it is valid. If not, it is removed. 
        for index, mac in enumerate(mac_list):
            # replace all instances of '-' with ':'
            mac_list[index] = mac.replace("-", ":")
            # Log the extracted mac address if it is still invalid
            if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
                context().logger.warning(f"{mac} is not a valid MAC address. {mac} will not be imported")
                mac_list.remove(mac)
                
        return mac_list

class HostnameResultProcessor(ResultProcessor):

    def __init__(self, config, data_handler) -> None:
        super().__init__(config, data_handler)
        self.hostnames = {}
        self.edge_count['asset_hostname'] = 0
        self.edge_dict['asset_hostname'] = []
        self.collection_dict['hostname'] = ([], '_key')

    def process_hostnames(self, response_json):

        edge_name = "asset_hostname"
        collection_name = self.config['collection'] # hostname

        for item in response_json:

            hostname = item['ASSET_HOSTNAME']
            asset_id = item['ASSET_ID']
            hostname_id = item['ASSET_HOSTNAME_ID']
            
            # Validates Hostnames
            hostname = self.validate_hostnames(hostname)
            
            self.add_edge(edge_name, {
                '_from_external_id': asset_id,
                '_to': "hostname/" + hostname,
                "external_id": hostname_id})

            self.edge_count[edge_name] += 1

            if hostname in self.hostnames:
                continue
            else:
                self.hostnames[hostname] = True
                self.add_collection_item(collection_name, {'_key': hostname})
                self.item_count += 1


        self.handle_remaining_collection_and_edge_items()

    def update_hostnames(self, response_json):

        hostname_ids = []
        for item in response_json:
            hostname_ids.append(item['ASSET_HOSTNAME_ID'])

        self.delete('asset_hostname', hostname_ids)

        self.process_hostnames(response_json)


    def delete_hostnames(self, response_json):
      
        hostname_ids = []
        for item in response_json:
            hostname_ids.append(item['VULNASSET_TRACKING_DELETED_ID'])
            self.item_count += 1

        self.delete('asset_hostname', hostname_ids)

    def validate_hostnames(self, hostname):
        
        regex = "[&#^|?<>\][]"

        # If any of the invalid characters &#^|?<>][ are found, remove them from the hostname string
        if re.search(regex, hostname):
            context().logger.warning(f"{hostname} contains invalid characters. Invalid characters will be removed.")
            hostname = re.sub(regex, "", hostname)
        
        return hostname


class AssetResultProcessor(ResultProcessor):

    def __init__(self, config, data_handler) -> None:
        super().__init__(config, data_handler)
        self.assets = {}
        self.collection_dict['asset'] = ([], 'external_id')

    def process_asset_ids(self, response_json):
        
        for item in response_json:

            asset_id = item['ASSET_ID']

            if asset_id not in self.assets:
                self.assets[asset_id] = {}

    def process_asset_properties(self, response_json):

        for item in response_json:         

            asset_id = item['ASSET_ID']
            asset_prop_type = item['ASSET_PROPERTY_TYPE_NAME']
            asset_prop_value = item['ASSET_PROPERTY_VALUE']   

            if asset_id not in self.assets:
                self.assets[asset_id] = {asset_prop_type: asset_prop_value}
            else:
                self.assets[asset_id][asset_prop_type] = asset_prop_value
    
    def process_asset_custom_properties(self, response_json):

        asset_custom_properties_identifier = ':'

        for item in response_json:         

            asset_id = item['ASSET_ID']
            asset_prop_type = item['ASSET_PROPERTY_TYPE_NAME']
            asset_prop_value = item['ASSET_PROPERTY_VALUE']          
            asset_prop_type_id = item['ASSET_PROPERTY_TYPE_ID']

            self.assets[asset_id][asset_prop_type] = asset_prop_value

            if int(asset_prop_type_id) >= 1000000000:                
                self.assets[asset_id][asset_custom_properties_identifier + asset_prop_type] = asset_prop_value

    def complete_collection(self):

        asset_custom_properties_identifier = ':'

        collection_name = self.config['collection'] # asset

        for k, v in self.assets.items():

            asset = {'external_id': k}

            name = None
            given_name = v.get('Given Name', None)
            unified_name =  v.get('Unified Name', None)

            if given_name:
                name = v['Given Name'] 
            elif unified_name:
                name = v['Unified Name']
            else:
                # Send the asset_id as the name if we can't get a name
                name = k

            asset['name'] = name

            if 'Description' in v:
                asset['description'] = v['Description']

            if 'Business Owner' in v:
                asset['business_owner'] = v['Business Owner']

            if 'Business Contact' in v:
                asset['business_contact'] = v['Business Contact']

            if 'Technical Owner' in v:
                asset['technical_owner'] = v['Technical Owner']

            if 'Technical Contact' in v:
                asset['technical_contact'] = v['Technical Contact']

            if 'Location' in v:
                asset['location'] = v['Location']

            if 'Asset Type' in v:
                asset['asset_type'] = v['Asset Type']
            
            for value in v:
                if asset_custom_properties_identifier in value:
                    new_value=value.replace(asset_custom_properties_identifier,'',1)
                    asset[new_value] = v[value]

            self.add_collection_item(collection_name, asset)
            self.item_count += 1

        self.handle_remaining_collection_and_edge_items()     

    def update_asset_ids(self, response_json):

        asset_ids =[]
        for item in response_json:
            asset_ids.append(item['ASSET_ID'])

        self.delete('asset', asset_ids)

        self.process_asset_ids(response_json)

    def delete_asset_ids(self, response_json):

        asset_ids = []
        for item in response_json:
            asset_ids.append(item['VULNASSET_TRACKING_DELETED_ID'])
            self.item_count += 1

        self.delete('asset', asset_ids)
           



class PortResultProcessor(ResultProcessor):

    def __init__(self, config, data_handler) -> None:
        super().__init__(config, data_handler)
        self.ports = {}
        self.edge_count['port_vulnerability'] = 0
        self.edge_count['ipaddress_port'] = 0
        self.edge_dict['port_vulnerability'] = []
        self.edge_dict['ipaddress_port'] = []
        self.collection_dict['port'] = ([], 'external_id')

    def process_ports(self, response_json):

        port_vuln = "port_vulnerability" 
        ip_port = "ipaddress_port"
        collection_name  = self.config['collection'] # port

        for item in response_json:

            vulninstance_id = item.get("VULNINSTANCE_ID")
            port_num = item.get("VULNINSTANCE_PORT_NUMBER")
            port_service = item.get("VULNINSTANCE_PORT_SERVICE")
            port_description = item.get("VULNINSTANCE_PORT_DESCRIPTION")
            ip = item.get("VULNINSTANCE_IPADDRESS")

            if context().args.incremental_supported:
                port_id = item.get("VULNINSTANCE_PORT_ID")
            else:
                port_id = str(vulninstance_id) + str(port_num)


            if port_id in self.ports:
                continue

            port = {}

            if port_service:
                port['protocol'] = port_service

            if port_description:
                port['description'] = port_description

            port['external_id'] = port_id
            port['port_number'] = int(port_num)

            self.ports[port_id] = True

            self.add_collection_item(collection_name, port)
            self.item_count += 1

            if vulninstance_id:
                self.add_edge(port_vuln, {
                    '_from_external_id': port_id,
                    '_to_external_id': vulninstance_id,
                    "external_id": port_id})
                self.edge_count[port_vuln] += 1

            if ip:

                self.add_edge(ip_port, {
                    '_from': "ipaddress/"+ip,
                    '_to_external_id': port_id,
                    "external_id": port_id})
                self.edge_count[ip_port] += 1

        
        self.handle_remaining_collection_and_edge_items()

    def update_ports(self, response_json):

        port_ids =[]
        for item in response_json:
            port_ids.append(item['VULNINSTANCE_PORT_ID'])

        self.delete('port_vulnerability', port_ids)
        self.delete('ipaddress_port', port_ids)

        self.process_ports(response_json)

    def delete_ports(self, response_json):
        
        port_ids = []

        for item in response_json:
            port_ids.append(item['VULNASSET_TRACKING_DELETED_ID'])
            self.item_count += 1

        self.delete('port', port_ids)


class UserResultProcessor(ResultProcessor):

    def __init__(self, config, data_handler) -> None:
        super().__init__(config, data_handler)
        self.users = {}
        self.edge_count['user_account'] = 0
        self.edge_count['asset_account'] = 0
        self.other_collections_count['account'] = 0

        self.edge_dict['user_account'] = []
        self.edge_dict['asset_account'] = []
        self.collection_dict['user'] = ([], 'external_id')
        self.collection_dict['account'] = ([], 'external_id')
        self.collection_dict['userbehaviour'] = ([], 'external_id')

    def process_users(self, response_json):

        usr = 'user'
        acc = 'account'
        usr_acc = "user_account"
        ass_acc = "asset_account"

        for item in response_json:

            username = item['ASSET_USERNAME']
            asset_id = item['ASSET_ID']
            user_id = item['ASSET_USERNAME_ID']

            if user_id in self.users:
                continue
            else:
                self.users[user_id] = True
                self.add_collection_item(usr, {'username': username, 'external_id': user_id})
                self.item_count += 1

                # Creat an account for the user
                self.add_collection_item(acc, {'name': username, 'external_id': user_id})
                self.other_collections_count[acc] += 1

                # Link the user to the account
                self.add_edge(usr_acc, {
                    '_from_external_id': user_id,
                    '_to_external_id': user_id,
                    'external_id': user_id})
                self.edge_count[usr_acc] += 1

                # Link the account to the asset
                self.add_edge(ass_acc, {
                    '_from_external_id': asset_id,
                    '_to_external_id': user_id,
                    'external_id': user_id})

                self.edge_count[ass_acc] += 1


        self.handle_remaining_collection_and_edge_items()

    def update_users(self, response_json):

        username_ids = []
        for item in response_json:
            username_ids.append(item['ASSET_USERNAME_ID'])

        self.delete('user_account', username_ids)
        self.delete('asset_account', username_ids)

        self.process_users(response_json)

    def delete_users(self, response_json):

        user_ids = []

        for item in response_json:
            user_ids.append(item['VULNASSET_TRACKING_DELETED_ID'])
            self.item_count += 1

        self.delete('user', user_ids) 

    def remove_uba_values(self):

        uba_ids = ['0']
        response = context().asset_server.get_uba_car_data()

        if response.status_code == 200:
            car_uba = json.loads(response.content)

            for item in car_uba:
                uba_ids.append(item['external_id'])

            context().logger.debug("Removing UBA data with ids: " + str(uba_ids))
            self.delete('userbehaviour', uba_ids)
        else:
            context().logger.info("Unable to remove UBA data from CAR")

    def process_uba_values(self, response_json):

        self.remove_uba_values()

        userbehaviour = 'userbehaviour'

        for item in response_json['users']:
            try:
                # String values to be imported
                userbehaviourProps = {
                    "id": str(item['id']),
                    "username":item['username'],
                    "manager":item['manager'],
                    "member_of":item['member_of'],
                    "custom_group":item['custom_group'],
                    "alert":item['alert'],
                    "input_username":item['input_username'],
                    "full_name":item['full_name'],
                    "dept":item['dept'],
                    "job_title":item['job_title'],
                    "email":item['email'],
                    "display_name":item['display_name'],
                    "state":item['state'],
                    "city":item['city'],
                    "country":item['country'],
                    "watson_search_id":item['watson_search_id']
                }

                # Iterates through each key:value in userbehaviourProps to change any values that are set to None (Null) to ""
                # Schema validation fails using car-framework v3.0.1+ if any of these values are set to None, as it is trying to check if they are of type String.
                for key in userbehaviourProps:
                    if  userbehaviourProps[key]== None:
                        userbehaviourProps[key] = ""

                # Number values to be imported
                risk = item['risk']
                risk_poll_count = item['risk_poll_count']
                prolonged_risk = item['prolonged_risk']
                latest_risk = item['latest_risk']
                trending = item['trending']
                investigation_started = item['investigation_started']
                investigation_expires = item['investigation_expires']
                watched = item['watched']
                last_offense_time = item['last_offense_time']
                watson_search_date = item['watson_search_date']

                # Boolean values to be imported
                in_job_title_peer_group_watchlist = item['in_job_title_peer_group_watchlist']
                in_ml_abridged_watch_list = item['in_ml_abridged_watch_list']
                in_dept_peer_group_watchlist = item['in_dept_peer_group_watchlist']
                trusted_user = item['trusted_user']

                self.add_collection_item(userbehaviour,{'external_id': userbehaviourProps["id"], 'risk': risk, 'username': userbehaviourProps["username"], 'manager': userbehaviourProps["manager"], 'member_of': userbehaviourProps["member_of"], 
                'custom_group': userbehaviourProps["custom_group"],'risk_poll_count': risk_poll_count, 'trending': trending, 'prolonged_risk': prolonged_risk, 'investigation_started': investigation_started,
                'investigation_expires': investigation_expires, 'watched': watched, 'alert': userbehaviourProps["alert"], 'input_username': userbehaviourProps["input_username"], 
                'full_name': userbehaviourProps["full_name"], 'dept': userbehaviourProps["dept"], 'job_title': userbehaviourProps["job_title"], 'email': userbehaviourProps["email"], 'latest_risk': latest_risk, 'display_name': userbehaviourProps["display_name"], 
                'state': userbehaviourProps["state"], 'city': userbehaviourProps["city"], 'country': userbehaviourProps["country"], 'in_job_title_peer_group_watchlist': in_job_title_peer_group_watchlist, 'in_ml_abridged_watch_list': in_ml_abridged_watch_list,
                'last_offense_time': last_offense_time, 'watson_search_id': userbehaviourProps["watson_search_id"], 'watson_search_date': watson_search_date, 'in_dept_peer_group_watchlist': in_dept_peer_group_watchlist,
                'trusted_user': trusted_user})
            except:
                if "input_username" in item:
                    context().logger.debug("UBA data for user '" + item['input_username'] + "' not found")
                else:
                    context().logger.debug("UBA data for user not found")



        self.handle_remaining_collection_and_edge_items()

