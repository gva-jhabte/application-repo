"""
CVE_SUMMARY
"""

import datetime, os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
sys.path.insert(1, os.path.join(sys.path[0], '../..'))
import va_dt_common.common as dt
import va_dt_common.json_lists as jl
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
SOURCE_BLOB = config.get('source_blob')

NVD_CVE_SUMMARY_BLOB = config.get('nvd_cve_summary_blob')
MFL_LIST_BLOB = config.get('mfl_list_blob')
CVES_WITH_EXPLOITS_BLOB = config.get('cves_with_exploits_blob')

TARGET_PROJECT = config.get('target_project')
TARGET_BUCKET = config.get('target_bucket')
TARGET_BLOB = config.get('target_blob')
    

def main():

    # keep a record of key data items so we can log what we've done
    with Auditor(JOB_NAME, r'../../config/va_auditor.yaml') as auditor:

        # set up a temp file for saving to
        # set the auditor to automatically track the written records 
        temp_file = dt.temp_file(JOB_NAME, auditor)

        # create a list of the CVEs in these two sets
        mfl_blob = dt.select_file_records(SOURCE_PROJECT, SOURCE_BUCKET, MFL_LIST_BLOB)
        mfl_index = set(jl.create_index(mfl_blob, 'CVE'))
        edb_blob = dt.select_file_records(SOURCE_PROJECT, SOURCE_BUCKET, CVES_WITH_EXPLOITS_BLOB)
        edb_index = set(jl.create_index(edb_blob, 'CVE'))
        
        # the main loop
        for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, NVD_CVE_SUMMARY_BLOB):        
            for nvd_cve_summary_line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
                record = json.loads(nvd_cve_summary_line)

                result = {}
                result['CVE'] = record.get('CVE')
                
                if record['v2.0'] != {}:
                    result['Confidentiality'] = record['v2.0'].get('confidentialityImpact')
                    result['Integrity'] = record['v2.0'].get('integrityImpact')
                    result['Availability'] = record['v2.0'].get('availabilityImpact')
                    result['UserInteraction'] = record['v2.0'].get('userInteractionRequired')
                    result['BaseScore'] = record['v2.0'].get('baseScore')
                elif record['v3.0'] != {}:
                    result['Confidentiality'] = record['v3.0'].get('confidentialityImpact')
                    result['Integrity'] = record['v3.0'].get('integrityImpact')
                    result['Availability'] = record['v3.0'].get('availabilityImpact')
                    result['UserInteraction'] = record['v3.0'].get('userInteraction')
                    result['BaseScore'] = record['v3.0'].get('baseScore')
                else:
                    result['Confidentiality'] = ''
                    result['Integrity'] = ''
                    result['Availability'] = ''
                    result['UserInteraction'] = '' 
                    result['BaseScore'] = ''

                # could have also implemented by adding an MFL=True
                # column to the MFL set and joined on CVE
                result = jl.set_value(result, 'MFL', lambda x: x.get('CVE') in mfl_index)
                result = jl.set_value(result, 'Exploit_Known', lambda x: x.get('CVE') in edb_index)
                temp_file.write_json_line(result)
                
        # save the temp file to the bucket
        temp_file.save_to_bucket(TARGET_PROJECT, TARGET_BUCKET, TARGET_BLOB)

        
main()
