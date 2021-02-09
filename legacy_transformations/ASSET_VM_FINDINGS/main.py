"""
ASSET_VM_FINDINGS
"""

import datetime
import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
sys.path.insert(1, os.path.join(sys.path[0], '../..'))
import va_dt_common.common as dt
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
VM_FINDINGS_BLOB = config.get('qvm_findings_blob')
CMDB_GRAPH_BLOB = config.get('cmdb_graph_blob')

TARGET_PROJECT = config.get('target_project')
TARGET_BUCKET = config.get('target_bucket')
TARGET_BLOB = config.get('target_blob')


def load_cmdb_graph(JOB_NAME, SOURCE_PROJECT, SOURCE_BUCKET, SOURCE_BLOB):
    graph_file = dt.temp_file(JOB_NAME + '_GRAPH')    
    # copy the graph file
    for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, SOURCE_BLOB):
        print(blob.name)
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


def find_record_in_graph(graph, ip, host):
    # start at the the IP address and walk from there
    search = gt.walk_from(graph, [ip], depth=2)
    
    # extract out the three components
    server = gt.select_nodes_by_type(search, 'ci_server')
    ips = gt.select_nodes_by_type(search, 'ip_address')
    apps = gt.select_nodes_by_type(search, 'service')
    
    server = list(server)
    
    # if we have more than one match on IP, try to match on the name,
    # the situation here is that CMDB has multiple hosts with the
    # same IP, we're assuming this is incorrect on CMDB so we'll
    # limit the matches down.
    if len(server) > 1:
        
        server_match = [x for x, y in search.nodes(data=True) if y.get('display_name') == host]
        
        if len(server_match) == 1:
            server = server_match
    
    if len(server) == 0:
        return {}
    
    server = server[0]
    ci_server = graph.nodes()[server]

    line = {
            "HOST_NAME": ci_server.get('display_name'),
            "ASSET_TYPE": ci_server.get('asset_type'),
            "ASSET_SUBTYPE": ci_server.get('asset_subtype'),
            "DNS": ci_server.get('dns_domain'),
            "ENVIRONMENT": ci_server.get('environment'),
            "FQDN": ci_server.get('fqdn'),
            "HOST_SUPPORT_GROUP": ci_server.get('support_group'),
            "CMDB_OS": ci_server.get('os'),
            "CMDB_OS_VERSION": ci_server.get('os_version'),
            "IS_VIRTUAL": ci_server.get('is_virtual'),
            "DEPLOYMENT_MODEL": ci_server.get('cloud_deployment_model'),
            "IP": get_attr(graph, ips, 'display_name'),
            "APPLICATION": get_attr(graph, apps, 'display_name'),
            "CBP": get_attr(graph, apps, 'cbp_category'),
            "APP_SUPPORT_GROUP": get_attr(graph, apps, 'support_group'),
            "SOX": get_attr(graph, apps, 'sox'),
            "STEWARD": get_attr(graph, apps, 'steward')
    }

    return line


def main(run_date):
    
    # keep a record of key data items so we can log what we've done
    with Auditor(data_set=JOB_NAME) as auditor:
        
        graph = load_cmdb_graph(JOB_NAME, SOURCE_PROJECT, SOURCE_BUCKET, CMDB_GRAPH_BLOB)

        # set up a temp file for saving to
        # set the auditor to automatically track the written records 
        temp_file = dt.temp_file(JOB_NAME, auditor)
        
        # the main processing loop
        for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET,
                                         VM_FINDINGS_BLOB + '.*' + datetime.date.strftime(run_date, '%Y-%m-%d')):
            
            print(blob.name)
            
            for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
                auditor.records_read = auditor.records_read + 1
                vm_finding = json.loads(line)
                by_ip = find_record_in_graph(graph, vm_finding.get('IP'), vm_finding.get('NETBIOS'))
                merged = {**vm_finding, **by_ip}
                temp_file.write_json_line(merged)
        
        blob_name = TARGET_BLOB.replace('%date', '%Y-%m-%d')
        blob_name = run_date.strftime(blob_name)
    
        temp_file.save_to_bucket(TARGET_PROJECT, TARGET_BUCKET, blob_name)


def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days) + 1):
        yield start_date + datetime.timedelta(n)
        

#for d in daterange(datetime.date(2020, 9, 15), datetime.date.today()):
#    main(d)
main(datetime.date.today())
