import os
import time
import sys
import requests
import subprocess

from subprocess import *
from car_framework.context import context
from car_framework.app import BaseApp
from car_framework.extension import SchemaExtension
from car_framework.util import RecoverableFailure

from connector.full_import import FullImport
from connector.inc_import import IncrementalImport
from connector.server_access import QRadarApi

version = '3.1'
#  python app.py -qradar-host "" -qradar-port "" -qradar-token "" -car-service-url "" -car-service-key "" -car-service-password "" -source "" -qradar-cert-path "" -qradar-uba ""

class App(BaseApp):
    def __init__(self):
        super().__init__('This script is used for pushing asset data to CP4S CAR ingestion microservice')
        # Add parameters need to connect data source
        self.parser.add_argument('-qradar-host', dest='host',  default=os.getenv('CONNECTION_HOST',None), type=str, required=False, help='The IP or FQDN of the target QRadar instance')
        self.parser.add_argument('-qradar-port', dest='port',  default=os.getenv('CONNECTION_PORT','443'), type=str, required=False, help='The port of the target QRadar instance')
        if os.environ.get('CONFIGURATION_AUTH_SEC'):
            self.parser.add_argument('-qradar-token', dest='token',  default=os.getenv('CONFIGURATION_AUTH_SEC',None), type=str, required=False, help='The \'Authorized Services\' token for the QRadar instance')
        elif os.environ.get('CONFIGURATION_AUTH_AUTHORIZED_SERVICES_TOKEN'):
            self.parser.add_argument('-qradar-token', dest='token',  default=os.getenv('CONFIGURATION_AUTH_AUTHORIZED_SERVICES_TOKEN',None), type=str, required=False, help='The \'Authorized Services\' token for the QRadar instance')    
        else:
            self.parser.add_argument('-qradar-token', dest='token',  default=os.getenv('QRADAR_API_KEY',None), type=str, required=False, help='The \'Authorized Services\' token for the QRadar instance')
        self.parser.add_argument('-retain_reports', action='store_true', dest='retain_reports', default=False, help='Backup the generated reports')
        self.parser.add_argument('-qradar-uba', dest='uba',  default=os.getenv('CONNECTION_UBA','False'), type=str, required=False, help='Enable access the UBA API')
        self.parser.add_argument('-concurrency', dest='concurrency',  default=os.getenv('CONCURRENCY_FLAG','True'), type=str, required=False, help='Disable / enable concurrency.')

    def setup(self):
        super().setup()

        if not context().args.host:
            context().logger.error("QRadar hostname not provided. Set 'CONNECTION_HOST' environment variable or provide with '-qradar-host' argument")
            sys.exit(2)

        if not context().args.token:
            context().logger.error("QRadar Authorized Services Token not provided. Set 'CONFIGURATION_AUTH_AUTHORIZED_SERVICES_TOKEN' environment variable or provide with '-qradar-token' argument")
            sys.exit(2)

        context().full_importer = FullImport()
        context().inc_importer = IncrementalImport()
        context().app_dir = os.path.dirname(os.path.realpath(__file__))
        context().args.api_version = "15.0"
        context().args.cert_path=None

        #Look for a certificate for self-signed QRadar hosts 
        if os.environ.get('CONNECTION_SELFSIGNEDCERT'):

            with open('/tmp/cert.crt', 'w') as fh:
                fh.write(str(os.environ.get('CONNECTION_SELFSIGNEDCERT')))
            
            context().args.cert_path="/tmp/cert.crt"
        
        cert_verification = context().args.cert_path if  context().args.cert_path else True
        context().asset_server = QRadarApi(context().args.host, context().args.port, context().args.api_version, context().args.token, cert_verification)

        
    
    def get_schema_extension(self):

        try:

            # schema extension: Assets Business Context
            self.assets_business_context = None
            # Check for schema extension support                
            car_api_key = context().args.api_key
            car_password = context().args.api_password
            car_extension_url = context().args.car_service_apikey_url.replace('v2','v3',1) + '/extensionSchema'
            check_car_extension = subprocess.Popen(["curl -s -u " + car_api_key + ":" + car_password + " " + car_extension_url + " | grep -c html"], shell=True, stdout=subprocess.PIPE).stdout
            check_support = check_car_extension.read().decode().strip()
            if check_support == '0':
                # The following extension adds new fields to "asset" and "userbehaviour" collections
                self.assets_business_context = SchemaExtension(
                key = 'E707D42D-C8E1-46B7-BD99-F13FE737BBBB',   # dev generated UUID key
                owner = 'CAR QRadar Connector',
                version = '2',
                schema = '''
                {
                    "vertices": [                    
                        {
                            "name": "asset",
                            "properties": {
                                "business_owner": {
                                    "type": "text",
                                    "description": "Asset business owner"
                                },
                                "business_contact": {
                                    "type": "text",
                                    "description": "Contact information for asset business owner"
                                },
                                "technical_owner": {
                                    "type": "text",
                                    "description": "Asset technical owner"
                                },
                                "technical_contact": {
                                    "type": "text",
                                    "description": "Contact information for asset technical owner"
                                },
                                "location": {
                                    "type": "text",
                                    "description": "Asset location information"
                                }
                            }   
                        },
                        {
                            "name": "userbehaviour",
                            "properties": {
                                "id": {
                                    "type" : "text",
                                    "description": "Identifier"
                                },
                                "risk": {
                                    "type" : "numeric",
                                    "description": "Risk related to the user behaviour"
                                },
                                "username": {
                                    "type" : "text",
                                    "description": "Username of User"
                                },
                                "manager": {
                                    "type" : "text",
                                    "description": "Manager of User"
                                },
                                "member_of": {
                                    "type" : "text",
                                    "description": "Groups user is a member of"
                                },
                                "custom_group": {
                                    "type" : "text",
                                    "description": "Custom group"
                                },
                                "risk_poll_count": {
                                    "type" : "numeric",
                                    "description": "Risk poll count"
                                },
                                "trending": {
                                    "type" : "numeric",
                                    "description": "1 if trending, 0 if it is not trending"
                                },
                                "prolonged_risk": {
                                    "type" : "numeric",
                                    "description": "Prolonged risk related to the user behaviour"
                                },
                                "investigation_started": {
                                    "type" : "numeric",
                                    "description": "Time when investigation started"
                                },
                                "investigation_expires": {
                                    "type" : "numeric",
                                    "description": "Time when investigation expires"
                                },
                                "watched": {
                                    "type" : "numeric",
                                    "description": "1 if Watched, 0 if not watched"
                                },
                                "alert": {
                                    "type" : "text",
                                    "description": "User behaviour alert"
                                },
                                "input_username": {
                                    "type" : "text",
                                    "description": "Input username"
                                },
                                "full_name": {
                                    "type" : "text",
                                    "description": "Full name of user"
                                },
                                "dept": {
                                    "type" : "text",
                                    "description": "Department name"
                                },
                                "job_title": {
                                    "type" : "text",
                                    "description": "User Job Title"
                                },
                                "email": {
                                    "type" : "text",
                                    "description": "User Email"
                                },
                                "latest_risk": {
                                    "type" : "numeric",
                                    "description": "Latest risk related to the user behaviour"
                                },
                                "display_name": {
                                    "type" : "text",
                                    "description": "Display Name"
                                },
                                "state": {
                                    "type" : "text",
                                    "description": "Users State"
                                },
                                "city": {
                                    "type" : "text",
                                    "description": "Users City"
                                },
                                "country": {
                                    "type" : "text",
                                    "description": "Users Country"
                                },
                                "in_job_title_peer_group_watch_list": {
                                    "type" : "boolean",
                                    "description": "True if in job title peer group watch list, false if not in job title peer group watch list"
                                },
                                "in_ml_abridged_watch_list": {
                                    "type" : "boolean",
                                    "description": "True if in ML abridged watch list, false if not in ML abridged watch list"
                                },
                                "last_offense_time": {
                                    "type" : "numeric",
                                    "description": "Last offense time"
                                },
                                "watson_search_id": {
                                    "type" : "text",
                                    "description": "ID of Watson search"
                                },
                                "watson_search_date": {
                                    "type" : "numeric",
                                    "description": "Date Watson search was performed"
                                },
                                "in_dept_peer_group_watchlist": {
                                    "type" : "boolean",
                                    "description": "True if in department peer group watch list, false if not in department peer group watch list"
                                },
                                "trusted_user": {
                                    "type" : "boolean",
                                    "description": "True if trusted user, false if not trusted user"
                                }
                            }
                        }
                    ]            
                }
                '''
            )   
                context().logger.info(f"CAR schema extension successfully applied")                                       
            else:
                context().logger.info(f"CAR API " + car_extension_url + " does not support schema extensions")

        except requests.exceptions.ConnectionError as e:
            context().logger.error(e)
            raise RecoverableFailure("Unable to connect to CAR API")

        return self.assets_business_context
        
if __name__ == "__main__":
    start = time.perf_counter()
    app = App()
    app.setup()
    app.run()

    end = time.perf_counter()
    time_took = end - start
    context().logger.debug(f"Time took: {time_took}")
