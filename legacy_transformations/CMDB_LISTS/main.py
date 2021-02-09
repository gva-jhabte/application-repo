"""
CMDB_LISTS

Merge the individual files for each of the CMDB files, the treatment
is exactly the same, so we have a generic routine which we send
the details which are different, the place of the source files and
the place for the resultant merged list,
"""

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
sys.path.insert(1, os.path.join(sys.path[0], '../..'))
from va_auditor import Auditor
import va_dt_common.common as dt
try:
    import ujson as json
except ImportError:
    import json


CONFIG_FILE = 'config.yaml'
config = dt.read_config(CONFIG_FILE)
SOURCE_PROJECT = config.get('source_project')
SOURCE_BUCKET = config.get('source_bucket')
TARGET_PROJECT = config.get('target_project')
TARGET_BUCKET = config.get('target_bucket')


def process_job(job_name, source_blob, target_blob):

    # keep a record of key data items so we can log what we've done
    with Auditor(data_set=job_name) as auditor:
        # set up a temp file for saving to
        # set the auditor to automatically track the written records
        temp_file = dt.temp_file(job_name, auditor)

        # we can't be sure today's files will be present, so look for the latest files
        for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, source_blob):
            # we want the whole file, so download it all at once.
            payload = blob.download_as_string()
            json_block = json.loads(payload)
            for json_record in json_block:
                auditor.records_read = auditor.records_read + 1
                temp_file.write_json_line(json_record)

        temp_file.save_to_bucket(TARGET_PROJECT, TARGET_BUCKET, target_blob)


def main():
        
    for job_name in config.get('jobs'):
        
        print(job_name)
        
        source_blob = config.get('source_blob').replace('%job', job_name)
        target_blob = config.get('target_blob').replace('%job', job_name)

        process_job(job_name, source_blob, target_blob)


main()
