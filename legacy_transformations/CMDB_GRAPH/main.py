"""
CMDB_GRAPH

Create a graph of the CMDB data which filters and joins the data
from the numerous tables we have from the CMDB.
"""

import networkx as nx
import os
import sys
import re
sys.path.insert(1, os.path.join(sys.path[0], '..'))
sys.path.insert(1, os.path.join(sys.path[0], '../..'))
import va_dt_common.common as dt
import graph_tools as gt
try:
    import ujson as json
except ImportError:
    import json


CONFIG_FILE = 'config.yaml'
config = dt.read_config(CONFIG_FILE)

JOB_NAME = config.get('job_name')
TEMP_FILE = dt.temp_file(JOB_NAME)
SOURCE_PROJECT = config.get('source_project')
SOURCE_BUCKET = config.get('source_bucket')

CI_SERVER_BLOB = config.get('ci_server_blob')
RELATIONSHIP_BLOB = config.get('relationship_blob')
CI_SERVICE_DISCOVERED_BLOB = config.get('service_discovered_blob')
PC_HARDWARE_BLOB = config.get('pc_hardware_blob')

TARGET_PROJECT = config.get('target_project')
TARGET_BUCKET = config.get('target_bucket')
TARGET_BLOB = config.get('target_blob')

ERRORBIN_PROJECT = config.get('errorbin_project')
ERRORBIN_BUCKET = config.get('errorbin_bucket')
ERRORBIN_BLOB = config.get('errorbin_blob')


def extract_sysid(url):
    try:
        if url == None:
            return ''
        parts = url.split('/')
        return parts[-1]
    except:
        print(url)
        return ''


def denull(value, default=''):
    if value is None:
        return default
    return value


def isIPv4_part(s):
    try: 
        return str(int(s)) == s and 0 <= int(s) <= 255
    except: 
        return False


def isIPv6_part(s):
    if len(s) > 4:
        return False
    try: 
        return int(s, 16) >= 0 and s[0] != '-'
    except:
        return False


def isIP(IP):
    if IP.count(".") == 3 and all(isIPv4_part(i) for i in IP.split(".")):
        return True
    if IP.count(":") == 7 and all(isIPv6_part(i) for i in IP.split(":")):
        return True
    return False


cmdb_graph = nx.DiGraph()

errorbin = dt.temp_file(JOB_NAME+'-errorbin')

counter = 0
print('adding relationships')
for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, RELATIONSHIP_BLOB):
    for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
        try:
            record = json.loads(line)
            counter = counter + 1

            # pre-defined edges - most aren't needed but we can't tell at this point
            parent_sys_id = extract_sysid(record.get('parent_link'))
            child_sys_id = extract_sysid(record.get('child_link'))

            # predefined relationships cover both directions, so 
            # split the type and build the reciprocal relationship
            relationship = record.get('type_display_value', 'unknown by::unknown to').split('::')
            cmdb_graph.add_edge(child_sys_id, parent_sys_id, relationship=relationship[0])
            #cmdb_graph.add_edge(parent_sys_id, child_sys_id, relationship=relationship[1])

            if counter % 500000 == 0:
                print(counter)           
                
        except:
            error_type = sys.exc_info()[0]
            print('row {} failed to load ({}bytes), {}'.format(counter, len(line), error_type))
            errorbin.write_text_line('')
            errorbin.write_text_line('row:{}, blob:{}, error:{}'.format(counter, blob.name, error_type))
            errorbin.write_text_line(line)

print("Status: {} nodes and {} edges".format(len(cmdb_graph.nodes), len(cmdb_graph.edges)))
print(gt.list_nodes(cmdb_graph))
            

counter = 0
print('adding servers')
for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, CI_SERVER_BLOB):
    for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name, chunk_size=10*1024*1024):
        try:
            record = json.loads(line)
            counter = counter + 1
            
            # remove servers which have been disposed
            if record.get('install_status') != 'Disposed':

                # create nodes for each of the servers
                cmdb_graph.add_node(denull(record.get('sys_id')), 
                                    node_type='ci_server',
                                    asset_type='server',
                                    asset_subtype=denull(record.get('u_subcategory')),
                                    display_name=denull(record.get('name')),
                                    dns_domain=denull(record.get('dns_domain')),
                                    environment=denull(record.get('u_environment')),
                                    fqdn=denull(record.get('fqdn')),
                                    support_group=denull(record.get('support_group_display_value')),
                                    os=denull(record.get('os')),
                                    os_version=denull(record.get('os_version')),
                                    is_virtual=denull(record.get('virtual')),
                                    cloud_deployment_model=denull(record.get('u_cloud_deployment_model'))
                )

                # create nodes and edges for the ip addresses, they appear as a 
                # list in the server records. IP addresses appear to be manually 
                # keyed, different separators are used
                for ip_address in re.split(',|;|\s', record.get('ip_address')):
                    cleaned_ip = ip_address.strip()
                    if isIP(cleaned_ip):
                        cmdb_graph.add_node(cleaned_ip, node_type = 'ip_address', display_name=cleaned_ip)
                        #cmdb_graph.add_edge(record.get('sys_id'), cleaned_ip, relationship='exposes') # asset exposes ip
                        cmdb_graph.add_edge(cleaned_ip, record.get('sys_id'), relationship='exposed by') # ip exposed by asset
                
            if counter % 50000 == 0:
                print(counter)

        except:
            error_type = sys.exc_info()[0]
            print('row {} failed to load ({}bytes), {}'.format(counter, len(line), error_type))
            errorbin.write_text_line('')
            errorbin.write_text_line('row:{}, blob:{}, error:{}'.format(counter, blob.name, error_type))
            errorbin.write_text_line(line)

print("Status: {} nodes and {} edges".format(len(cmdb_graph.nodes), len(cmdb_graph.edges)))
print(gt.list_nodes(cmdb_graph))


counter = 0
print('adding endpoints')
for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, PC_HARDWARE_BLOB):
    for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name, chunk_size=10 * 1024 * 1024):
        try:
            record = json.loads(line)
            counter = counter + 1

            # remove servers which have been disposed
            if record.get('install_status') != 'Disposed':

                # create nodes for each of the servers
                cmdb_graph.add_node(denull(record.get('sys_id')),
                                    node_type='ci_server',
                                    asset_type='workstation',
                                    asset_subtype=denull(record.get('u_subcategory')),
                                    display_name=denull(record.get('name')),
                                    dns_domain=denull(record.get('dns_domain')),
                                    environment=denull(record.get('u_environment')),
                                    fqdn=denull(record.get('fqdn')),
                                    support_group=denull(record.get('support_group_display_value')),
                                    os=denull(record.get('os')),
                                    os_version=denull(record.get('os_version')),
                                    is_virtual=denull(record.get('virtual')),
                                    cloud_deployment_model=denull(record.get('u_cloud_deployment_model'))
                                    )

                # create nodes and edges for the ip addresses, they appear as a
                # list in the server records. IP addresses appear to be manually
                # keyed, different separators are used
                for ip_address in re.split(',|;|\s', record.get('ip_address')):
                    cleaned_ip = ip_address.strip()
                    if isIP(cleaned_ip):
                        cmdb_graph.add_node(cleaned_ip, node_type='ip_address', display_name=cleaned_ip)
                        # cmdb_graph.add_edge(record.get('sys_id'), cleaned_ip, relationship='exposes') # asset exposes ip
                        cmdb_graph.add_edge(cleaned_ip, record.get('sys_id'),
                                            relationship='exposed by')  # ip exposed by asset

            if counter % 50000 == 0:
                print(counter)

        except:
            error_type = sys.exc_info()[0]
            print('row {} failed to load ({}bytes), {}'.format(counter, len(line), error_type))
            errorbin.write_text_line('')
            errorbin.write_text_line('row:{}, blob:{}, error:{}'.format(counter, blob.name, error_type))
            errorbin.write_text_line(line)

print("Status: {} nodes and {} edges".format(len(cmdb_graph.nodes), len(cmdb_graph.edges)))
print(gt.list_nodes(cmdb_graph))
            

counter = 0
print('adding applications')
for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, CI_SERVICE_DISCOVERED_BLOB):
    for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
        try:
            counter = counter + 1
            record = json.loads(line)
            
            record['u_cmdb_data_mgt_journal'] = ''

            # create nodes for applications
            cmdb_graph.add_node(record.get('sys_id'),
                                node_type='service',
                                display_name=denull(record.get('name')),
                                troux_id=denull(record.get('u_application_id')),
                                cbp_category=denull(record.get('u_cbp_tier')),
                                sox=denull(record.get('u_sox_control')),
                                steward=denull(record.get('u_cmdb_data_steward_display_value')),
                                support_group=denull(record.get('support_group_display_value'))
            )

            if counter % 5000 == 0:
                print(counter)
            
        except:
            error_type = sys.exc_info()[0]
            print('row {} failed to load ({}bytes), {}'.format(counter, len(line), error_type))
            errorbin.write_text_line('')
            errorbin.write_text_line('row:{}, blob:{}, error:{}'.format(counter, blob.name, error_type))
            errorbin.write_text_line(line)
            

nx.write_graphml(cmdb_graph, TEMP_FILE.file_name)

            
print("Status: {} nodes and {} edges".format(len(cmdb_graph.nodes), len(cmdb_graph.edges)))
print(gt.list_nodes(cmdb_graph))

errorbin.save_to_bucket(ERRORBIN_PROJECT, ERRORBIN_BUCKET, ERRORBIN_BLOB)   
nx.write_graphml(cmdb_graph, TEMP_FILE.file_name)
TEMP_FILE.save_to_bucket(TARGET_PROJECT, TARGET_BUCKET, TARGET_BLOB)
