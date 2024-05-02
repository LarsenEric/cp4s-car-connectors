import os
import json
import concurrent.futures
from time import time
from math import floor

from car_framework.full_import import BaseFullImport
from car_framework.context import context

import connector.result_processors as processors
from connector.data_handler import DataHandler

class FullImport(BaseFullImport):
    def __init__(self):
        super().__init__()
        # initialize the data handler.
        self.data_handler = DataHandler()

    # Create source, report and source_report entry.
    def create_source_report_object(self):
        return self.data_handler.create_source_report_object()


    # GEt save point from server
    def get_new_model_state_id(self):
        # If server doesn't have save point it can just return current time
        # So that it can be used for next incremental import
        return floor(time())


    def run(self):
        super().run()

    def import_vertex(self, config):

        collection = config['collection']

        processor = getattr(processors, collection.title() + "ResultProcessor")(config, self.data_handler)
        processor.run()

        return (self.data_handler.collections, self.data_handler.collection_keys, self.data_handler.edges, self.data_handler.edge_keys)
    

    # Import all vertices from data source
    def import_vertices(self):

        if context().args.concurrency == "True":        
            
            self.import_vertices_concurrently()
        
        else:

            vertex_config_dir = context().app_dir + "/config/vertices"

            for vertex in os.scandir(vertex_config_dir):
                
                if vertex.is_file and os.path.splitext(vertex.name)[1] == ".json" and not vertex.name.startswith('.'):

                    with open (vertex.path) as fh:

                        config = json.load(fh)
                        collection = config['collection']

                        processor = getattr(processors, collection.title() + "ResultProcessor")(config, self.data_handler)
                        processor.run()

        #import UBA data if use UBA API is set to "True"
        if context().args.uba == "True":
            #import UBA data if supported
            context().asset_server.check_uba_supported()
            if context().args.uba_supported: 
                processor = getattr(processors, "UserResultProcessor")('uba', self.data_handler)
                processor.run_uba()
        else:
            context().logger.info(f"Access to UBA API is Disabled.") 

        if context().args.retain_reports: self.data_handler.retain_reports()
        if context().args.debug: self.data_handler.verify_reports()
        
        self.data_handler.send_collections(self)          
                            

    def import_vertices_concurrently(self):

        vertex_config_dir = context().app_dir + "/config/vertices"


        configs = []

        for vertex in os.scandir(vertex_config_dir):
            
            if vertex.is_file and os.path.splitext(vertex.name)[1] == ".json" and not vertex.name.startswith('.'):

                with open (vertex.path) as fh:

                    configs.append(json.load(fh))    
                    
                            
        with concurrent.futures.ProcessPoolExecutor() as executer:

            context().logger.info("Starting processes")
            results = executer.map(self.import_vertex, configs)
            
            
            for result in results:

                (collections, collection_keys, edges, edge_keys) = result

                self.data_handler.collections.update(collections)

                self.data_handler.collection_keys.update(collection_keys)

                self.data_handler.edges.update(edges)

                self.data_handler.edge_keys.update(edge_keys)


    # Imports edges for all collection
    def import_edges(self):
        
        self.data_handler.send_edges(self)
