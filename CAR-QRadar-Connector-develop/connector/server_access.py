import json
import requests
import time
import subprocess

from subprocess import *
from car_framework.context import context
from car_framework.util import RecoverableFailure, UnrecoverableFailure
from car_framework.server_access import BaseAssetServer
from requests_toolbelt.adapters import host_header_ssl

class NoCallbackError(UnrecoverableFailure):

    def __init__(self) -> None:
        super().__init__("No callback was supplied to handle the request results")

class QRadarAPIError(RecoverableFailure):

    def __init__(self, message):
        super().__init__(message)

class QRadarApi(BaseAssetServer):

    def __init__(self, hostname, port, api_version, sec_token, cert) -> None:
        super().__init__()

        self.url = f"https://{hostname}:{port}/api/"
        self.api_ver = api_version
        self.sec_token = sec_token
        self.cert_path = cert
        self.headers = {"Version": self.api_ver, "SEC": self.sec_token}
        self.session = requests.Session()
        self.session.mount('https://', host_header_ssl.HostHeaderSSLAdapter())
        self.ds_endpoints = {
            "post-query":"dynamic_search/searches",
            "get-query-status" : "dynamic_search/searches/{}?fields=status",
            "get-query-results" : "dynamic_search/searches/{}/results"
        }
        self.uba_endpoints = {
            "above-threshold":"console/plugins/{}/app_proxy/api/users_above_threshold",
            "bulk-user":"console/plugins/{}/app_proxy/api/bulk_user_info",#parameter required - '{"users":["USER_NAME”, “USER2_NAME”,“USER3_NAME”]}’     ---- curl -k -H 'Content-Type:application/json' -H 'Accept:application/json'-H 'SEC:SEC_TOKEN' -X POST -d '{"users":["USER_NAME”, “USER2_NAME”,“USER3_NAME”]}’ https://QR_IP_ADDRESS/console/plugins/UBA_APP_ID/app_proxy/api/bulk_user_info
            "investigated-list":"console/plugins/{}/app_proxy/api/investigated_list",
            "risky-users":"console/plugins/{}/app_proxy/api/top_10_risky_users",
            "user-anomalies":"console/plugins/{}/app_proxy/api/top_ten_users_anomalies",
            "single-user":"console/plugins/{}/app_proxy/api/user_info?username=testUser",#user name required 
            "user-risk":"console/plugins/{}/app_proxy/api/risk?username=testUser",#user name required
            "uba-offenses":"console/plugins/{}/app_proxy/api/uba_offenses"
        }
        self.uba_headers = {"SEC": self.sec_token, "Accept":"application/json", "Content-Type":"application/json"}
        self.uba_url = f"https://{hostname}:{port}/"

    def post(self, endpoint, data):

        try:

            response = self.session.post(self.url + endpoint, data=json.dumps(data), headers=self.headers, proxies=None, verify=self.cert_path)

            self.check_response_for_issues(response)

            return response

        except requests.exceptions.ConnectionError as e:
            context().logger.error(e)
            raise RecoverableFailure("Unable to connect to QRadar Host")


    def get(self, endpoint):

        try:

            response = self.session.get(self.url + endpoint, headers=self.headers, proxies=None, verify=self.cert_path)

            self.check_response_for_issues(response)

            return response

        except requests.exceptions.ConnectionError as e:
            context().logger.error(e)
            raise RecoverableFailure("Unable to connect to QRadar Host")

    def post_uba(self, endpoint, data):

        try:

            response = self.session.post(self.uba_url + endpoint, data=json.dumps(data), headers=self.uba_headers, proxies=None, verify=self.cert_path)

            self.check_response_for_issues(response)

            return response

        except requests.exceptions.ConnectionError as e:
            context().logger.error(e)
            raise RecoverableFailure("Unable to connect to QRadar Host")

    def get_uba(self, endpoint):

        try:

            response = self.session.get(self.uba_url + endpoint, headers=self.uba_headers, proxies=None, verify=self.cert_path)

            self.check_response_for_issues(response)

            return response

        except requests.exceptions.ConnectionError as e:
            context().logger.error(e)
            raise RecoverableFailure("Unable to connect to QRadar Host")

    def check_response_for_issues(self, response):

        status = response.status_code

        if status == 401:
            raise QRadarAPIError(f"Unauthorised connection to QRadar, check 'Authorized Services' token. [Status = {status}]")
        elif status == 422:
            raise QRadarAPIError(f"The requested API version does not exist on the host. Check documentation to see supported QRadar versions. [Status = {status}]")
        elif status != 200 and status != 201:
            context().logger.error(f"Response message: {response.json().get('message', '')}")
            raise QRadarAPIError(f"Unknown QRadar API error. [Status = {status}]")

        
    def get_system_information(self):

        endpoint = "system/about"
        response = self.get(endpoint)

        return response.json()
        
    def check_qradar_connection(self):

        context().logger.info("Checking QRadar connection.")

        self.get_system_information()

        context().logger.info("Connected to QRadar successfully.")
            
    def test_connection(self):
        
        try:
           self.get_system_information()
           code = 0
        except:
            code = 1
            
        return code
    
    def check_if_vuln_id_available(self, major, build_no):

        vuln_id_available = False

        if (major == 743 and build_no > 20210517144015)  or major >= 744:
            vuln_id_available = True

        return vuln_id_available

    def check_if_incremental_supported(self, major, build_no):

        incremental_supported = False

        # setting supported versions to greater than 7.4.3 FixPack 5 & 7.5.0 UpdatePackage 1, IS_GAC
        if (major == 743 and build_no >= 20220307203834) or (major >= 750 and build_no >= 20220215133427):
            incremental_supported = True

        return incremental_supported

    def qradar_version_check(self):

        context().logger.info("Checking QRadar version.")

        sys_info = self.get_system_information()

        # {'release_name': '7.4.2', 'build_version': '2020.7.0.20200915173208', 'external_version': '7.4.2'}
        
        major_version = int(sys_info.get('external_version').replace('.',''))
        build_no = int(sys_info.get('build_version').split('.')[3])

        context().args.vuln_id_available = self.check_if_vuln_id_available(major_version, build_no)
        context().args.incremental_supported = self.check_if_incremental_supported(major_version, build_no)

    def check_if_query_is_finished(self, response):

        waiting_responses = ["INITIALIZING", "PAUSED", "PROCESSING", "QUEUED", "RESUMING", "POSTED", "QUEUED", "RUNNING"]
        failed_responses = ["ERROR", "CANCELLED", "CANCELING", "CANCEL_REQUESTED", "CONFLICT", "EXCEPTION", "INTERRUPTED"]
        
        if response.status_code == 200 and response.json()['status'] in waiting_responses:
            time.sleep(1)
            return False

        response_json = response.json()

        if response_json['status'] in failed_responses:
            raise UnrecoverableFailure(f"Query failed with status '{response.json()['status']}'")

        return True


    def get_query_from_file(self, file):

        file_dir = context().app_dir + "/config/queries/"+file

        with open (file_dir) as fh:
            return json.load(fh)

    def process_ds_query_response(self, response):

        if response.status_code == 201:

            response_json = response.json()

            handle = response_json['handle']
            column_map = {}

            # Create a column map to be used later when reading results 
            for item in response_json['header']['columns']:
                column_map[item['field']['contextual_type']] = item['column_name']
            
            return handle, column_map

    def rename_query_result_columns(self, response_json, column_map):

        '''
        Dynamic Search API returns results like 
        {
            'column1': 'value',
            'column2': 'value',
            ...
        }

        Update the results with proper column names using the created earlier
        '''

        renamed_columns = []
        
        while len(response_json) > 0:

            item = response_json.pop()['columns']

            new_dict = {}
            for key in column_map.keys():

                new_dict[key] = item[column_map[key]]
            
            renamed_columns.append(new_dict)

        return renamed_columns



    def run_dynamic_search(self, query, page_limit=1000000, callback = None):

        if not callback: raise NoCallbackError
        
        offset = 0
        while True:
            
            # Dynamic search takes 'offset' and 'limit' query attributes to perform paging
            query["query"]['range']['offset'] = offset
            query["query"]['range']['limit'] = page_limit

            # Post the query, recieve a handle to track the query, and coulumn mapping information
            handle_response = self.post(self.ds_endpoints.get('post-query'), query)

            # Extract the column map and handle from the response
            handle, column_map = self.process_ds_query_response(handle_response)

            query_complete = False
            while not query_complete:
                # Wait for the query to complete
                status_response = self.get(self.ds_endpoints.get('get-query-status').format(handle))
                query_complete = self.check_if_query_is_finished(status_response)
            
            # Get the query results 
            result_response = self.get(self.ds_endpoints.get('get-query-results').format(handle))

            if result_response.status_code == 200:
                
                response_json = result_response.json()
                response_item_count = len(response_json)
                # Save memory on large resposes 
                del(result_response)

                if response_item_count > 0:
                    # Process the batch
                    response_json = self.rename_query_result_columns(response_json, column_map)
                    callback(response_json)

                if response_item_count < page_limit:
                    # All results obtained
                    break

                offset += page_limit

    def get_uba_car_data(self):

        car_url = context().args.car_service_apikey_url + '/userbehaviour?source=' + context().args.source
        car_token = context().args.api_token
        req_header = {'Accept' : 'application/json', 'Authorization': 'car-token ' + str(car_token)}
            
        response = requests.get(car_url, headers=req_header)
        
        return response


    def check_uba_supported(self):

        uba_supported= False

        try:
            # Check if UBA is installed
            if self.get_uba_app_id():
                # Check if correct UBA version is installed
                if self.check_uba_version():
                    # Check for schema extension support                
                    car_api_key = context().args.api_key
                    car_password = context().args.api_password
                    car_extension_url = context().args.car_service_apikey_url.replace('v2','v3',1) + '/extensionSchema'
                    check_car_extension = subprocess.Popen(["curl -s -u " + car_api_key + ":" + car_password + " " + car_extension_url + " | grep -c html"], shell=True, stdout=subprocess.PIPE).stdout
                    check_support = check_car_extension.read().decode().strip()
                    if check_support == '0':
                        uba_supported = True
                    else:
                        context().logger.info(f"UBA schema extension does not exist")
                else:
                    context().logger.info(f"Installed UBA app version is incorrect. UBA data import requires installation of UBA app version 4.1.9 or later on the QRadar data source.")
            else:
                context().logger.info(f"UBA API access enabled: Yes, UBA app installed: No. UBA data import requires installation of UBA app version 4.1.9 or later on the QRadar data source.")
        except:
            context().logger.error("Error determining UBA status")

        context().args.uba_supported = uba_supported


    def get_uba_app_id(self):
        uba_response = self.get('gui_app_framework/named_services')

        if uba_response.status_code == 200: 

            uba_json = uba_response.json()
            uba_record = [x for x in uba_json if x['name'] == 'uba-cp4s']
            if len(uba_record) > 0:

                return uba_record[0].get('application_id')


    def check_uba_version(self):
        uba_response = self.get('gui_app_framework/named_services')

        if uba_response.status_code == 200:

            uba_json = uba_response.json()
            uba_record = [x for x in uba_json if x['name'] == 'uba-cp4s']
            
            if len(uba_record) > 0:
                # Sets the minimum version and installed UBA app version.
                minimum_version = "4.1.9"
                uba_version = uba_record[0].get('version')
                # Return True if the installed version is equal to or greater than the minimum version (0 or 1)
                # Return False if the installed version is less than the minimum version (-1)
                if self.compare_uba_version(minimum_version, uba_version) >= 0:
                    return True
                else:
                    return False

    def compare_uba_version(self, minimum_version, uba_version):
                # Changes the version string into a list of numbers
                minimum_version_split = [int(v) for v in minimum_version.split(".")]
                uba_version_split = [int(v) for v in uba_version.split(".")]
                
                # Goes through each list and compares each number, once a number from the installed UBA version is found to be greater; return 1,
                # or once a number from the installed UBA version is found to be smaller; return -1, if all is equal then return 0.
                for i in range(max(len(minimum_version_split),len(uba_version_split))):
                    num1 = minimum_version_split[i] if i < len(minimum_version_split) else 0
                    num2 = uba_version_split[i] if i < len(uba_version_split) else 0
                    if num1 < num2:
                        return 1
                    elif num1 > num2:
                        return -1
                return 0
            
    def run_uba_query(self, callback = None):

        #Get UBA app id to be used by the query
        uba_app_id = self.get_uba_app_id()

        #get list of usernames for uba query 
        data=self.get_uba_users()
        users = []
        for user in data:
            users.append(user['ASSET_USERNAME'])

        #format list of usernames for query
        #data = json.loads('{"users":[' + ','.join([f"'{value}'" for value in (','.join(str(x) for x in users)).split(',')]).replace('"','').replace('\'','"') + ']}')
        string = ','.join(str(x) for x in users)
        string_list = [f"'{value}'" for value in string.split(',')]
        formatted_string = ','.join(string_list).replace('"','').replace('\'','"')
        data_query = '{"users":[' + formatted_string + ']}'
        data = json.loads(data_query)

        response_json = self.post_uba('console/plugins/'+str(uba_app_id)+'/app_proxy/api/bulk_user_info', data).json()

        callback(response_json)


    def get_uba_users(self):

        #get the list of users to run the uba query      
        file_dir = context().app_dir + "/config/queries/query-user.json"
        with open(file_dir) as fh:
                query= json.load(fh)

        handle_response = self.post(self.ds_endpoints.get('post-query'), query)

        # Extract the column map and handle from the response
        handle, column_map = self.process_ds_query_response(handle_response)

        query_complete = False
        while not query_complete:
            # Wait for the query to complete
            status_response = self.get(self.ds_endpoints.get('get-query-status').format(handle))
            query_complete = self.check_if_query_is_finished(status_response)
            
        # Get the query results 
        result_response = self.get(self.ds_endpoints.get('get-query-results').format(handle))

        if result_response.status_code == 200:
                
            response_json = result_response.json()
            response_item_count = len(response_json)
            # Save memory on large resposes 
            del(result_response)

            if response_item_count > 0:
                # Process the batch
                response_json = self.rename_query_result_columns(response_json, column_map)   
        
        return response_json

