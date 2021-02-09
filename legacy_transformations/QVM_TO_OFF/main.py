"""
QVM_TO_OFF

Create a Qualys Vulnerability Scan JSONL file.
"""

import datetime, os, sys
import xmltodict
sys.path.insert(1, os.path.join(sys.path[0], '..'))
sys.path.insert(1, os.path.join(sys.path[0], '../..'))
from va_auditor import Auditor
import va_dt_common.common as dt


CONFIG_FILE = 'config.yaml'
config = dt.read_config(CONFIG_FILE)

JOB_NAME = config.get('job_name')
TEMP_FILE = dt.get_temp_file(JOB_NAME)
SOURCE_PROJECT = config.get('source_project')
SOURCE_BUCKET = config.get('source_bucket')
SOURCE_BLOB = config.get('source_blob')
KB_SOURCE_BLOB = config.get('kb_source_blob')
TARGET_PROJECT = config.get('target_project')
TARGET_BUCKET = config.get('target_bucket')
TARGET_BLOB = config.get('target_blob')


def extract_details(line, qids):
    """
    Interpret each line of data from the file, load into XML and then extract the required data
    """
    try:
        host = xmltodict.parse(line)['HOST']
    except Exception as ex:
        print(f"Exception parsing line: {ex}")
        print(line)
        return

    CONFIDENCES = {'Info': 'low', 'Potential': 'medium', 'Confirmed': 'high'}

    # need something for the hostname, so fall back to the internal host ID
    hostname = host.get('DNS') or host.get('NETBIOS') or 'ID:' + host.get('ID')
    ipv4 = host.get('IP')
    ipv6 = host.get('IPV6')
    operating_system = host.get('OS')

    detections = host.get('DETECTION_LIST')['DETECTION']
    if not type(detections) is list:
        detections = [detections]

    for detection in detections:
        # use the FQDN from the detection entry if it exists
        hostname = detection.get('FQDN') or hostname
        # get the QID details from the KB if they exist
        if qids.get(detection.get('QID')) is not None:
            qid_name = qids.get(detection.get('QID'))[0]
            # description maxLength is 256
            qid_desc = qids.get(detection.get('QID'))[1][:255]
        else:
            qid_name = detection.get('QID')
            qid_desc = 'N/A'
        off_entry = {'name': qid_name,
                     'description': qid_desc}
        if detection.get('RESULTS') is not None:
            off_entry['detail'] = detection.get('RESULTS')
        off_entry['severity'] = int(detection.get('SEVERITY'))
        off_entry['confidence'] = CONFIDENCES[detection.get('TYPE')]
        off_entry['timestamp'] = detection.get('LAST_FOUND_DATETIME')
        off_entry['location'] = {'hostname': hostname}
        if ipv4 is not None:
            off_entry['location']['ipv4'] = ipv4
        if ipv6 is not None:
            off_entry['location']['ipv6'] = ipv6
        if detection.get('PORT') is not None:
            off_entry['location']['port'] = int(detection.get('PORT'))
        if detection.get('PROTOCOL') is not None:
            off_entry['location']['protocol'] = detection.get('PROTOCOL')
        off_entry['source'] = 'QUALYS'

        off_entry['tags'] = []
        if operating_system is not None:
            off_entry['tags'] = [x.strip() for x in operating_system.split('/')]

        off_entry['references'] = []
        off_entry['references'].append({
            "QID": detection.get('QID')
        })

        yield off_entry


def extract_kb(line):
    """
    Interpret each line of data from the file, load into XML and then extract the required data
    """

    try:
        vuln = xmltodict.parse(line)['VULN']
    except:
        print(line)
        return

    qid = vuln.get('QID')
    title = vuln.get('TITLE')
    diagnosis = vuln.get('DIAGNOSIS') or 'N/A'

    kb = {}

    if qid is not None:
        kb[qid] = [title, diagnosis]

    return kb


def main():

    # keep a record of key data items so we can log what we've done
    auditor = Auditor(JOB_NAME, r'../../config/va_auditor.yaml')
    auditor.commencement_time = datetime.datetime.today()

    # make sure the temp file isn't there from a previous run
    if os.path.exists(TEMP_FILE):
        os.remove(TEMP_FILE)

    # get details of qids from KB files
    qids = {}
    for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, KB_SOURCE_BLOB):
        for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
            try:
                qids.update(extract_kb(line))

            except Exception as ex:
                print(f"Exception in processing KB entries: {ex}")
                print(line)
                sys.exit()

    # main loop
    for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, SOURCE_BLOB):
        for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
            auditor.records_read = auditor.records_read + 1
            try:
                records = extract_details(line, qids)

            except Exception as ex:
                print(f"Exception in extracting QVM record: {ex}")
                print(line)
                sys.exit()

            for record in records:
                try:
                    dt.write_json_line(record, TEMP_FILE)
                    auditor.records_written = auditor.records_written + 1

                except Exception as ex:
                    print(f"Exception in writing json line: {ex}")
                    print(record)
                    sys.exit()

    dt.save_file_to_bucket(TEMP_FILE, TARGET_PROJECT, TARGET_BUCKET, TARGET_BLOB)

    # clean up the temp file
    if os.path.exists(TEMP_FILE):
        os.remove(TEMP_FILE)

    auditor.completion_time = datetime.datetime.today()
    auditor.log_event()


main()
