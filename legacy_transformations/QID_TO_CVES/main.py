"""
QID_TO_CVES

Create a lookup table to map single QIDs to multiple CVEs.
"""

import datetime, os, sys
import json
sys.path.insert(1, os.path.join(sys.path[0], '..'))
sys.path.insert(1, os.path.join(sys.path[0], '../..'))
from va_auditor import Auditor
import va_dt_common.common as dt


CONFIG_FILE = 'config.yaml'
config = dt.read_config(CONFIG_FILE)

JOB_NAME = config.get('job_name')
SOURCE_PROJECT = config.get('source_project')
SOURCE_BUCKET = config.get('source_bucket')
SOURCE_BLOB = config.get('source_blob')
TARGET_PROJECT = config.get('target_project')
TARGET_BUCKET = config.get('target_bucket')
TARGET_BLOB = config.get('target_blob')


def extract_details(line):
    """
    Interpret each line of data from the file, load into JSON and then extract the required data
    """
    try:
        parsed_line = json.loads(line)
    except:
        print(line)
        return

    return [parsed_line['QID'], parsed_line['CVE']]


def main(run_date):

    # keep a record of key data items so we can log what we've done
    with Auditor(JOB_NAME, r'../../config/va_auditor.yaml') as auditor:

        # set up a temp file to save the records to
        temp_file = dt.temp_file(JOB_NAME, auditor)

        records = {}

        # the main loop
        for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET,
                                         SOURCE_BLOB + '.*' + datetime.date.strftime(run_date, '%Y-%m-%d')):
            for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
                details = extract_details(line)
                if details[0] in records:
                    records[details[0]].append(details[1])
                else:
                    records[details[0]] = [details[1]]

        for record in records:
            json_line = {"QID": record, "CVES": records[record]}
            temp_file.write_json_line(json_line)

        blob_name = TARGET_BLOB.replace('%date', '%Y-%m-%d')
        blob_name = run_date.strftime(blob_name)
        temp_file.save_to_bucket(TARGET_PROJECT, TARGET_BUCKET, blob_name)


def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days) + 1):
        yield start_date + datetime.timedelta(n)


#for d in daterange(datetime.date(2020, 9, 16), datetime.date.today()):
main(datetime.date.today())
