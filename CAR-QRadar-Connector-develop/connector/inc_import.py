import json
import os

from car_framework.inc_import import BaseIncrementalImport
from car_framework.context import context
from car_framework.util import IncrementalImportNotPossible

from connector.data_handler import DataHandler
import connector.result_processors as processors


class IncrementalImport(BaseIncrementalImport):
    def __init__(self):
        super().__init__()
        # initialize the data handler.
        self.data_handler = DataHandler()
        self.create_source_report_object()

    # Pulls the save point for last import
    def get_new_model_state_id(self):
        return str(self.data_handler.timestamp)

    # Create source, report and source_report entry.
    def create_source_report_object(self):
        return self.data_handler.create_source_report_object()

    # Gather information to get data from last save point and new save point
    def get_data_for_delta(self, last_model_state_id, new_model_state_id):
        return None

    # Import all vertices from data source
    def import_vertices(self):

        #import data that has been added/updated since last run
        self.run_queries(vertex_config_dir = context().app_dir + "/config/inc")
        #import uba data
        self.run_uba_query()

        if context().args.retain_reports: self.data_handler.retain_reports()
        if context().args.debug: self.data_handler.verify_reports()
        
        self.data_handler.send_collections(self)

    # Imports edges for all collection
    def import_edges(self):
        self.data_handler.send_edges(self)

    # Delete vertices that are deleted in data source
    def delete_vertices(self):

        self.run_queries(context().app_dir + "/config/del")

    def run_queries(self, vertex_config_dir):

        for vertex in os.scandir(vertex_config_dir):
                
                if vertex.is_file and os.path.splitext(vertex.name)[1] == ".json" and not vertex.name.startswith('.'):

                    with open (vertex.path) as fh:
                        config = json.load(fh)
                        collection = config['collection']

                        processor = getattr(processors, collection.title() + "ResultProcessor")(config, self.data_handler)
                        processor.run()

    def run_uba_query(self):
        #import UBA data if use UBA API is set to "True"
        if context().args.uba == "True":
            #import UBA data if supported - this is a full import as incremental is not supported on uba
            context().asset_server.check_uba_supported()
            if context().args.uba_supported: 
                processor = getattr(processors, "UserResultProcessor")('uba', self.data_handler)
                processor.run_uba()
        else:
            context().logger.info(f"Access to UBA API is Disabled.")
                        
    def run(self):
        
        context().asset_server.check_qradar_connection()
        context().asset_server.qradar_version_check()
        
        if not context().args.incremental_supported:
            raise IncrementalImportNotPossible('QRadar version does not support incremental updates.')
        
        super().run()
