import datetime
import concurrent.futures
import itertools
import os
import json

from car_framework.context import context
from car_framework.data_handler import BaseDataHandler
from car_framework.util import UnrecoverableFailure


def get_report_time():
    delta = datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)
    milliseconds = delta.total_seconds() * 1000
    return milliseconds


class DataHandler(BaseDataHandler):
    def __init__(self):
        super().__init__()

    def create_source_report_object(self):

        if not (self.source and self.report and self.source_report):
            self.source = {'_key': context().args.source, 'name': context().args.host, 'description': 'QRadar Assets and Vulnerabilities'}
            self.report = {'_key': str(self.timestamp), 'timestamp' : self.timestamp, 'type': 'Qradar', 'description': 'QRadar Assets and Vulnerabilities'}
            self.source_report = [{'active': True, '_from': 'source/' + self.source['_key'], '_to': 'report/' + self.report['_key'], 'timestamp': self.report['timestamp']}]

        return {'source': self.source, 'report': self.report, 'source_report': self.source_report}

    
    def create_edges(self, name, edge_list):

        while len(edge_list) > 0:
            item = edge_list.pop()
            self.add_edge(name, item)

    def create_edges_concurrently(self, data):

        name, edge_list = data
        data_len = len(edge_list)

        # Since edge_keys is a class variable we sometimes see this populated by other child processes     
        self.edge_keys[name] = []

        self.create_edges(name, edge_list)

        # We don't want to have to pass back the left-over edges so manually force them to be exported into a report 
        remainder_to_save = self.edges.get(name)
        if remainder_to_save and len(remainder_to_save) > 0:
            self._save_export_data_file(name, remainder_to_save)
            self.edges[name] = []

        if len(self.edge_keys.get(name)) > data_len:
                raise UnrecoverableFailure(f"Concurrency error: Expected to create {data_len} edge keys but there are {len(self.edge_keys.get(name))}")

        return self.edge_keys.get(name)
    
    def do_the_math(self, length):

        report_size  = context().args.export_data_page_size

        num_processes = min( (length//report_size) , 10)
        remainder = length % report_size

        return report_size, num_processes, remainder


    def handle_edge_list(self, name, edge_list):

        report_size, num_processes, remainder = self.do_the_math(len(edge_list))

        if num_processes >= 2:

            self._create_export_data_dir(name)

            # Split the edge_list in to x lists where x is the number of processes
            work_list = [(name, []) for _ in range(num_processes)]

            # Give the remainder items to the first child process
            for _ in range(remainder):
                work_list[0][1].append(edge_list.pop())


            i = itertools.cycle(range(num_processes))
            while len(edge_list) > 0:

                for _ in range(report_size):
                    work_list[next(i)][1].append(edge_list.pop())

            # We need to append keys that are returned from the child processes, so initialise the edge_keys list.
            if not self.edge_keys.get(name):

                self.edge_keys[name] = []

            original = self.edge_keys[name]
            self.edge_keys[name] = []

            with concurrent.futures.ProcessPoolExecutor() as executer:

                results = executer.map(
                    self.create_edges_concurrently, work_list)

                for result in results:

                    edge_keys = result

                    if edge_keys and len(edge_keys) > 0:
                        original.extend(edge_keys)

            self.edge_keys[name] = original

            # The edges list is used by the framework to identify which reports to send so need to create an empty list
            if not self.edges.get(name): self.edges[name] = []

        else:
            # Work sequentially if there are a small number of edges
            self.create_edges(name, edge_list)

    def create_collections(self, name, collection_list, key):

        while len(collection_list) > 0:
            item = collection_list.pop()
            self.add_collection(name, item, key)

    def create_collections_concurrently(self, data):

        name, collection_list, key = data
        data_len = len(collection_list)

        # Since collection_keys is a class variable we sometimes see this populated by other child processes
        self.collection_keys[name] = []

        self.create_collections(name, collection_list, key)

        # We don't want to have to pass back the left-over collections so manually force them to be exported into a report 
        remainder_to_save = self.collections.get(name)
        if remainder_to_save and len(remainder_to_save) > 0:
            self._save_export_data_file(name, remainder_to_save)
            self.collections[name] = []

        if len(self.collection_keys.get(name)) > data_len:
                raise UnrecoverableFailure(f"Concurrency error: Expected to create {data_len} collection keys but there are {len(self.collection_keys.get(name))}")

        return self.collection_keys.get(name)

    def handle_collection_list(self, name, collection_list, key):

        report_size, num_processes, remainder = self.do_the_math(len(collection_list))
        if num_processes >= 2:

            self._create_export_data_dir(name)

            # Split the collection_list in to x lists where x is the number of processes
            work_list = [(name, [], key) for _ in range(num_processes)]

            # Give the remainder items to the first child process
            for _ in range(remainder):
                work_list[0][1].append(collection_list.pop())


            i = itertools.cycle(range(num_processes))
            while len(collection_list) > 0:

                for _ in range(report_size):
                    work_list[next(i)][1].append(collection_list.pop())

            # We need to append keys that are returned from the child processes, so initialise the collection_keys list.
            if not self.collection_keys.get(name):

                self.collection_keys[name] = []

            original = self.collection_keys[name]
            self.collection_keys[name] = []

            with concurrent.futures.ProcessPoolExecutor() as executer:

                results = executer.map(
                    self.create_collections_concurrently, work_list)

                for result in results:

                    collection_keys = result

                    if collection_keys and len(collection_keys) > 0:
                        original.extend(collection_keys)

            self.collection_keys[name] = original

            # The collections list is used by the framework to identify which reports to send so need to create an empty list
            if not self.collections.get(name): self.collections[name] = []

        else:
            
            # Work sequentially if there are a small number of collection items
            self.create_collections(name, collection_list, key)

    def retain_reports(self):

        backup_report_dir = self.export_data_dir + "RETAINED"
        context().logger.info(f"Reports will be retained in {backup_report_dir}")

        for name, data in self.edges.items():
            # save residual data
            if len(data) > 0:
                self._save_export_data_file(name, data)
            data.clear()

        for name, data in self.collections.items():
            # save residual data
            if len(data) > 0:
                self._save_export_data_file(name, data)
            data.clear()

        import shutil

        if os.path.exists(self.export_data_dir):
            shutil.copytree(self.export_data_dir, backup_report_dir)

    def check_for_duplicate_keys(self, item_dict):

        for k, v in item_dict.items():

            key_dict = {}
            duplicate_item_count = 0

            for item in v:

                if key_dict.get(item):
                    key_dict[item] += 1
                else:
                    key_dict[item] = 1

            for key, count in key_dict.items():
                if count > 1:
                    #context().logger.debug(f"Edge_Key List {k} duplicates '{key}' {count} times!")
                    duplicate_item_count += 1
        
            if duplicate_item_count > 0:
                context().logger.debug(f"Key List {k} duplicates '{duplicate_item_count}' items!")

    def check_keys_and_report_items_are_equal_length(self, key_dict):
        
        for k, v in key_dict.items():

            itemcount = 0
            with os.scandir(os.path.join(self.export_data_dir, k)) as it:
                for f in it:
                    with open(f.path, 'r') as fh:
                        js = json.load(fh)
                        itemcount += len(js[k])
            
            if itemcount != len(v):
                context().logger.debug(f"{k}: report item count doesn't match key count. Keys = {len(v)}, Report_Items = {itemcount}")
    
    def check_for_duplicates_in_report(self):

        for key in self.edge_keys.keys():
            key_dict = {}

            with os.scandir(os.path.join(self.export_data_dir, key)) as it:
                for f in it:
                    with open(f.path, 'r') as fh:
                        js = json.load(fh)
                        for item in js[key]:
                            
                            k = '#'.join(str(x) for x in item.values())

                            if not key_dict.get(k):
                                key_dict[k] = 1
                            else:
                                key_dict[k] += 1
            
            for k, v in key_dict.items():
                if v > 1:
                    context().logger.debug(f"Reports for {key} contains duplicates")

        for key in self.collection_keys.keys():
            key_dict = {}

            with os.scandir(os.path.join(self.export_data_dir, key)) as it:
                for f in it:
                    with open(f.path, 'r') as fh:
                        js = json.load(fh)
                        for item in js[key]:
                            
                            k = '#'.join(str(x) for x in item.values())

                            if not key_dict.get(k):
                                key_dict[k] = 1
                            else:
                                key_dict[k] += 1
            
            for k, v in key_dict.items():
                if v > 1:
                    context().logger.debug(f"Reports for {key} contains duplicates")

                        



    def verify_reports(self):

        for name, data in self.edges.items():
            # save residual data
            if len(data) > 0:
                self._save_export_data_file(name, data)
            data.clear()

        for name, data in self.collections.items():
            # save residual data
            if len(data) > 0:
                self._save_export_data_file(name, data)
            data.clear()

        context().logger.debug("Checking for duplicate keys in memory...")

        self.check_for_duplicate_keys(self.edge_keys)   
        self.check_for_duplicate_keys(self.collection_keys)         

        context().logger.debug("Checking for json item count matches key count...")

        self.check_keys_and_report_items_are_equal_length(self.edge_keys)
        self.check_keys_and_report_items_are_equal_length(self.collection_keys)

        self.check_for_duplicates_in_report()
