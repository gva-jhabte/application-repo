import xmltodict
import json


FINDINGS_FILE = r'qualys_hosts.xml'
KB_FILE = r'qkb.xml'
SEVERITIES = ['Low', 'Low', 'Medium', 'Medium', 'High']
CONFIDENCES = {'Info': 'low', 'Potential': 'medium', 'Confirmed': 'high'}
OFF_DIR = r'output/'
OFF_FILE = r'offl.json'

# Get QIDs, TITLE and DIAGNOSIS from the knowledgebase
with open(KB_FILE) as kf:
    kb_doc = xmltodict.parse(kf.read())
qids = {}
for vuln in kb_doc['KNOWLEDGE_BASE_VULN_LIST_OUTPUT']['RESPONSE']['VULN_LIST']['VULN']:
    qid = vuln.get('QID')
    if qid is not None:
        title = vuln.get('TITLE')
        diagnosis = vuln.get('DIAGNOSIS') or 'N/A'
        qids[qid] = [title, diagnosis]
kb_doc = None

with open(FINDINGS_FILE) as ff:
    findings_doc = xmltodict.parse(ff.read())

hosts = findings_doc['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['HOST_LIST']

finding_count = 0
for host in hosts['HOST']:
    # We need something for the hostname, so fall back to the internal host ID
    hostname = host.get('DNS') or host.get('NETBIOS') or 'ID:' + host.get('ID')
    ipv4 = host.get('IP')
    ipv6 = host.get('IPV6')
    timestamp = host.get('LAST_VM_SCANNED_DATE')
    operating_system = host.get('OS')

    for finding in host['DETECTION_LIST']['DETECTION']:
        # Use the FQDN from the vulnerability entry if it exists
        hostname = host.get('FQDN') or hostname
        # description maxLength is 256
        off_entry = {'name': qids[finding.get('QID')][0],
                     'description': qids[finding.get('QID')][1][:255]}
        if finding.get('RESULTS') is not None:
            off_entry['detail'] = finding.get('RESULTS')
        off_entry['severity'] = int(finding.get('SEVERITY'))
        off_entry['confidence'] = CONFIDENCES[finding.get('TYPE')]
        off_entry['timestamp'] = finding.get('LAST_FOUND_DATETIME')
        off_entry['location'] = {'hostname': hostname}
        if ipv4 is not None:
            off_entry['location']['ipv4'] = ipv4
        if ipv6 is not None:
            off_entry['location']['ipv6'] = ipv6
        if finding.get('PORT') is not None:
            off_entry['location']['port'] = int(finding.get('PORT'))
        if finding.get('PROTOCOL') is not None:
            off_entry['location']['protocol'] = finding.get('PROTOCOL')
        off_entry['source'] = 'QUALYS'

        off_entry['tags'] = []
        if operating_system is not None:
            off_entry['tags'] = [x.strip() for x in operating_system.split('/')]

        off_entry['references'] = []
        off_entry['references'].append({
            "QID": finding.get("QID")
        })
        with open(OFF_DIR + str(finding_count) + '_' +  OFF_FILE, 'w') as off_file:
            off_file.write(json.dumps(off_entry, indent=2) + '\n')
        finding_count = finding_count + 1
