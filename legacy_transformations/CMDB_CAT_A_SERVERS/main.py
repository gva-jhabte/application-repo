"""
CMDB_CAT_A_SERVERS
"""

import datetime, os, sys, re
sys.path.insert(1, os.path.join(sys.path[0], '..'))
sys.path.insert(1, os.path.join(sys.path[0], '../..'))
import va_dt_common.common as dt
import va_dt_common.json_lists as jl
import csv
import tempfile
import graph_tools as gt
import networkx as nx
from va_auditor import Auditor
try:
    import ujson as json
except ImportError:
    import json


CONFIG_FILE = 'config.yaml'
config = dt.read_config(CONFIG_FILE)

JOB_NAME = config.get('job_name')
SOURCE_PROJECT = config.get('source_project')
SOURCE_BUCKET = config.get('source_bucket')
CMDB_GRAPH_BLOB = config.get('cmdb_graph_blob')

TARGET_PROJECT = config.get('target_project')
TARGET_BUCKET = config.get('target_bucket')
TARGET_BLOB = config.get('target_blob')
TARGET_CSV_BLOB = config.get('target_csv_blob')


def load_cmdb_graph(JOB_NAME, SOURCE_PROJECT, SOURCE_BUCKET, SOURCE_BLOB):
    graph_file = dt.temp_file(JOB_NAME + '_GRAPH')
    # copy the graph file
    for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, SOURCE_BLOB):
        with open(graph_file.file_name, 'wb') as file:
            blob.download_to_file(file)
    # open the graph file
    graph = nx.read_graphml(graph_file.file_name)
    print("Status: {} nodes and {} edges".format(len(graph.nodes), len(graph.edges)))
    return graph


def get_attr(graph, nodes, attr):
    if len(nodes) == 0:
        return ''
    ret = []
    for n in nodes:
        ret.append(graph.nodes()[n].get(attr))
    ret = list(set(ret))
    if len(ret) == 1:
        return ret[0]
    return ret


def main(run_date):
    # keep a record of key data items so we can log what we've done
    with Auditor(JOB_NAME, r'../../config/va_auditor.yaml') as auditor:

        graph = load_cmdb_graph(JOB_NAME, SOURCE_PROJECT, SOURCE_BUCKET, CMDB_GRAPH_BLOB)
        cat_a = gt.search_nodes(graph, {'cbp_category': 'Tier A'})

        # set up a temp file for saving to
        # set the auditor to automatically track the written records
        temp_file = dt.temp_file(JOB_NAME, auditor)

        # the main processing loop
        # walk the graph from each cat A application
        output = []
        for application in cat_a.nodes():
            app = graph.nodes()[application]
            app_graph = gt.walk_from(graph, [application], depth=1, reverse=True)
            for app_server in gt.select_nodes_by_type(app_graph, 'ci_server'):
                server = graph.nodes()[app_server]
                svr_graph = gt.walk_from(graph, [app_server], depth=1, reverse=True)
                has_ip = False
                for ip_addr in gt.select_nodes_by_type(svr_graph, 'ip_address'):
                    ip = graph.nodes()[ip_addr]
                    has_ip = True
                    line = {
                        'APPLICATION': app.get('display_name'),
                        'HOST_NAME': server.get('display_name'),
                        'DNS': server.get('dns_domain'),
                        'FQDN': server.get('fqdn'),
                        'CMDB_OS': server.get('os'),
                        'CMDB_OS_VERSION': server.get('os_version'),
                        'ENVIRONMENT': server.get('environment'),
                        'IP': ip.get('display_name')
                    }
                    output.append(line)
                    temp_file.write_json_line(line)
                # pick up the entries that don't have an IP address
                if not has_ip:
                    line = {
                        'APPLICATION': app.get('display_name'),
                        'HOST_NAME': server.get('display_name'),
                        'DNS': server.get('dns_domain'),
                        'FQDN': server.get('fqdn'),
                        'CMDB_OS': server.get('os'),
                        'CMDB_OS_VERSION': server.get('os_version'),
                        'ENVIRONMENT': server.get('environment'),
                        'IP': None
                    }
                    output.append(line)
                    temp_file.write_json_line(line)

        blob_name = TARGET_BLOB.replace('%date', '%Y-%m-%d')
        blob_name = run_date.strftime(blob_name)
        temp_file.save_to_bucket(TARGET_PROJECT, TARGET_BUCKET, blob_name)

        csv_blob_name = TARGET_CSV_BLOB.replace('%date', '%Y-%m-%d')
        csv_blob_name = run_date.strftime(csv_blob_name)

        # json_lists.save_as_csv() expects a filename not a file object and NamedTemporaryFile returns an object
        # so we're just reusing the logic here.
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf8', newline='') as temp_csv_file:
            record = output[0]
            columns = record.keys()
            csv_file = csv.DictWriter(temp_csv_file, fieldnames=columns)
            csv_file.writeheader()

            for record in output:
                record = jl.select_record_fields(record, columns)
                csv_file.writerow(record)
            dt.save_file_to_bucket(temp_csv_file.name, TARGET_PROJECT, TARGET_BUCKET, csv_blob_name)


def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days) + 1):
        yield start_date + datetime.timedelta(n)
        

#for d in daterange(datetime.date(2020, 9, 15), datetime.date.today()):
#    main(d)
main(datetime.date.today())
