"""
QVM All Report
Brings together all the enriched CVE data, and includes a derived triage for the CVEs
in question. Algorithm for the triage is below
"""

import datetime, os, sys
from datetime import timedelta
sys.path.insert(1, os.path.join(sys.path[0], '..'))
sys.path.insert(1, os.path.join(sys.path[0], '../..'))
import va_dt_common.common as dt
try:
    import ujson as json
except ImportError:
    import json

from google.cloud import storage


CONFIG_FILE = 'config.yaml'
config = dt.read_config(CONFIG_FILE)

JOB_NAME = config.get('job_name')
TEMP_FILE = dt.get_temp_file(JOB_NAME)
SOURCE_PROJECT = config.get('source_project')
SOURCE_BUCKET = config.get('source_bucket')
QID_SUMMARY_SOURCE_BLOB_PATH = config.get('QID_Summary_source_blob_path')
CVE_SUMMARY_SOURCE_BLOB_PATH = config.get('CVE_Summary_source_blob_path')
QID_CVE_SOURCE_BLOB_PATH = config.get('QID_CVE_source_blob_path')
ASSET_FINDINGS_SOURCE_BLOB_PATH = config.get('Asset_Findings_source_blob_path')
TARGET_PROJECT = config.get('target_project')
TARGET_BUCKET = config.get('target_bucket')
TARGET_BLOB = config.get('target_blob')

def Triage(CVEOnMFL, CVSS_score, exploitExists, UIRrequired, ServerIsProduction, serverCBP, 
            confidentialityImpact, integrityImpact, availabilityImpact):
    # Based upon current post-RV triage algo. Subject to update with time
    if CVEOnMFL:
        return 'High'
    else:
        if CVSS_score < 7:
            return 'Low'
        else:
            if exploitExists and not UIRrequired:
                # Vulnerability has an exploit and does not require user interaction
                return 'Medium'
            elif not exploitExists and UIRrequired:
                # Vulnerability has no exploit, and user interaction is required (i.e.lowest risk for these two)
                if ServerIsProduction:
                    if serverCBP == 'Tier A' or serverCBP == 'Tier B':
                        if confidentialityImpact == 'COMPLETE' or availabilityImpact == 'COMPLETE' or integrityImpact == 'COMPLETE':
                            # Only medium risk for prod and Tier A/B and complete impact
                            return 'Medium'
                        else:
                            return 'Low'
                    else:
                        return 'Low'
                else:   # Non-prod server
                    return 'Low'
            else: 
                # Vulnerability has either an exploit, or requires user interaction
                if ServerIsProduction:
                    if serverCBP == 'Tier A' or serverCBP == 'Tier B':
                        if confidentialityImpact == 'NONE' and availabilityImpact == 'NONE' and integrityImpact == 'NONE':
                            return 'Low'
                        else:
                            # Any sort of impact will result in this being medium risk on tier A/B systems
                            return 'Medium'
                    elif serverCBP == 'Tier C':
                        if confidentialityImpact == 'COMPLETE' or availabilityImpact == 'COMPLETE' or integrityImpact == 'COMPLETE':
                            # Tier C is medium risk only for complete C,I,A impact
                            return 'Medium'
                        else:
                            return 'Low'
                    else:
                        # Covers production servers with no CBP
                        return 'Low'
                else:   # Non-prod server
                    if serverCBP == 'Tier A' or serverCBP == 'Tier B':
                        return 'Medium'
                    else:
                        # Covers non-production servers with a CBP of C or no CBP
                        return 'Low'

def CVESummaryForQID(CVEsForQID):
    # Pick out the highest/worst ratings for a collection of CVEs returned for a given QID. Aggregate the CVE Ids
    # into a single string for return
    #
    # Initialise everything to the most gentle possible set of findings
    CVEs = ''
    Confidentiality = 'NONE'
    Availability = 'NONE'
    Integrity = 'NONE'
    BaseScore = 0
    UIRequired = True
    ExploitExists = False
    MFL = False
    MFLCVEs = ''
    MFLCount = 0    

    for key, row in CVEsForQID.items():  # Python's dict.items() gives a tuple of key, value. Not just an array of values
        # Concatenate CVE IDs
        CVEs = CVEs + row['CVE'] + ','

        # Set directly comparable values based upon whether a more severe value has been found
        if isinstance(row['BaseScore'], float) and row['BaseScore'] > BaseScore:
            BaseScore = row['BaseScore']
        if row['UserInteraction'] == False:
            UIRequired = False
        if row['Exploit_Known'] == True:
            ExploitExists = False
        if row['MFL'] == True:
            MFL = True
            # Build the MFL CVEs and count here as appropriate
            MFLCVEs = MFLCVEs + row['CVE'] + ','
            MFLCount = MFLCount+1

        # Set C,I,A based upon string comparisons. Possibly consider getting strings changed to enums in the source
        # allowing faster code of the sort above, but work with string extracts for now.
        if row['Confidentiality'].upper() == 'COMPLETE':
            Confidentiality = 'COMPLETE'
        elif row['Confidentiality'].upper() == 'PARTIAL' and Confidentiality == 'NONE':
            Confidentiality = 'PARTIAL'

        if row['Availability'].upper() == 'COMPLETE':
            Availability = 'COMPLETE'
        elif row['Availability'].upper() == 'PARTIAL' and Availability == 'NONE':
            Availability = 'PARTIAL'

        if row['Integrity'].upper() == 'COMPLETE':
            Integrity = 'COMPLETE'
        elif row['Integrity'].upper() == 'PARTIAL' and Integrity == 'NONE':
            Integrity = 'PARTIAL'


    # Been through all individual CVEs. Return the summary as a dictionary.
    if MFLCount > 0:
        MFLCVEs = MFLCVEs[:-1] # trim any trailing commas if there is any data present
    return {'CVE': CVEs[:-1], 'Confidentiality': Confidentiality, 'Integrity': Integrity, 'Availability': Availability,
            'UserInteraction': UIRequired, 'BaseScore': BaseScore, 'MFL': MFL, 'Exploit_Known': ExploitExists,
            'MFLCVEs':MFLCVEs, 'MFLCount': MFLCount}

def getMaxCBP(CBPFromFinding):
    # CBP is per service/application on an asset. This will manifest as being returned as a string if there is
    # only one, but a list of strings if more than one. Allow either to be processed by this method, seeking
    # to return the most significant value
    if CBPFromFinding is None:
        return ''
    elif type(CBPFromFinding) is str:
        return CBPFromFinding
    else: # This is a list (or similar) of strings representing multiple CPBs for an asset.
        CBPToReturn = ''
        for CBP in CBPFromFinding:
            if CBP is None:
                continue # a missing CBP value won't affect the returned rating
            elif CBP == 'Tier A':
                return 'Tier A' # No point in searching further
            elif CBP == 'Tier B':
                CBPToReturn = 'Tier B'  # Highest cat that doesn't cause the loop to break
            elif CBP == 'Tier C' and CBPToReturn == '':
                CBPToReturn = 'Tier C' # Only other possible value. Only set if if no CBP has been set before
                
    return CBPToReturn # All values checked, no Tier A found. Return what has been found.           
              

def main(run_date):

    # keep a record of key data items so we can log what we've done
    auditor = Auditor(JOB_NAME, r'../../config/va_auditor.yaml')
    auditor.commencement_time = datetime.datetime.today()

    # set up a temp file for saving to
    # set the auditor to automatically track the written records 
    temp_file = dt.temp_file(JOB_NAME, auditor)

    #Create QVM all report.

    # Takes in CVE summary (CVEId, CVSS data, QID, MFL/Exploit data). Key by CVEId
    # Takes in QID-CVE map. Can search by CVE or QID, many->many relationship
    # Takes in Asset findings (QVM == Qualys machine scan results, along with CMDB data. Key by QID, IP Address
    # Takes in Qualys descriptions and such like). Key by IP address
    # Once all data available, create triage rating based upon OLD triage algo and add. Then output as CSV(?)

    # Generator across Asset findings (each will have an IP, some CMDB data and a QID). Then get CVE from QIDCVEMap to get
    # CVE summary data. Get triage based upon compounded data from Triage subroutine, and add any QID description needed. 
    # Then output as csv (possibly? Still to do...)

    # Get CVE summary data
    CVESummaries = {}
    for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, CVE_SUMMARY_SOURCE_BLOB_PATH + '.*' + datetime.datetime.strftime(run_date, '%Y-%m-%d')): 
        for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
            data_record = json.loads(line)
            CVESummaries[data_record['CVE']] = data_record

    # Likewise QID summaries (will have the QID verbose description on it)
    QIDSummaries = {}
    for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, QID_SUMMARY_SOURCE_BLOB_PATH + '.*' + datetime.datetime.strftime(run_date, '%Y-%m-%d')): 
        for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
            data_record = json.loads(line)
            QIDSummaries[data_record['QID']] = data_record

    # And finally likewise the QID -> CVE map data. This is many <-> many, so collect it as sets of CVE Ids
    # which are keyed by the QID in question, as it will be searched by QID.
    CVEsForAllQIDs = {}
    for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, QID_CVE_SOURCE_BLOB_PATH + '.*' + datetime.datetime.strftime(run_date, '%Y-%m-%d')): 
        for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
            data_record = json.loads(line)
            if data_record['QID'] in CVEsForAllQIDs:
                # Add to existing set
                CVEsForAllQIDs[data_record['QID']].add(data_record['CVE'])
            else:
                # New item on dict creating a new set
                CVEsForAllQIDs[data_record['QID']] = {data_record['CVE']}

    # Now, parse the whole finding set retrieving the enrichment data from the existing indices
    for blob in dt.get_list_of_blobs(SOURCE_PROJECT, SOURCE_BUCKET, ASSET_FINDINGS_SOURCE_BLOB_PATH + '.*' + datetime.datetime.strftime(run_date, '%Y-%m-%d')): 
        for line in dt.read_blob_lines(SOURCE_PROJECT, SOURCE_BUCKET, blob.name):
            finding = json.loads(line)
            
            # Do some column renames where appropriate to match VSM reporting names
            finding['VulnID'] = finding.pop('QID')
            finding['ScanScore'] = finding.pop('SEVERITY')
            
            if 'ENVIRONMENT' in finding and not finding['ENVIRONMENT'] is None and finding['ENVIRONMENT'].upper()[:4] == 'PROD':
                serverIsProduction = True
            else:
                serverIsProduction = False
                
            if 'CBP' in finding:
                CBP = getMaxCBP(finding['CBP'])
                # Homogenise the values
                if 'NONE' in CBP.upper():
                    CBP = ''
            else:
                CBP = '' # Presumes no CBP if no data returned. May need to revisit
                
            # Return the CBP value to the findings dict so that its duplicates are eliminated
            finding['CBP'] = CBP
            
            # Add various keys that are missing in some cases with empty values to the 
            # finding so that the output data is consistent in the fields it presents

            if not 'PORT' in finding or finding['PORT'] is None:
                finding['PORT'] = ''
            if not 'SOX' in finding or finding['SOX'] is None:
                finding['SOX'] = 'false'
            if not 'STEWARD' in finding or finding['STEWARD'] is None:
                finding['STEWARD'] = ''
            if not 'CMDB_OS' in finding or finding['CMDB_OS'] is None:
                finding['CMDB_OS'] = ''
            if not 'CMDB_OS_VERSION' in finding or finding['CMDB_OS_VERSION'] is None:
                finding['CMDB_OS_VERSION'] = ''
                
            # Retrieve the QID summary for the finding
            if finding['VulnID'] in QIDSummaries:
                qidSummary = QIDSummaries[finding['VulnID']]
            else:
                # Got a QID with no summary, so build a dummy one. Should really not happen.
                qidSummary = {'QID': finding['VulnID'], 'Patchable': 'Unknown', 'Published_Date': 'Unknown', 'baseScore': 0,
                                'availabilityImpact': 'NONE', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE',
                                'VulnerabilityName': '', 'Category': '', 'Solution': '', 'VendorNotes': ''}
                
            # Get all the CVEs associated with the finding (may be more than one)
            if finding['VulnID'] in CVEsForAllQIDs:
                # Code to generate triage based upon matching CVE data
                CVEIdsForQID = CVEsForAllQIDs[finding['VulnID']]

                # Get all the summaries. The odd selector is Dictionary Comprehension syntax and can be read as
                # 'Create a new dictionary (keys:values) based on the keys and values from CVESummaries if the key for
                # an entry in CVESummaries is in CVEsForQID'
                CVESummariesForQID = {k:v for (k, v) in CVESummaries.items() if k in CVEIdsForQID}

                # Get a single line rollup of all the CVE data for the QID that can then be used for both triage and return data.
                cveSummaryForQID = CVESummaryForQID(CVESummariesForQID)

                # The triage will rely on the highest/worst values for any of the CVEs returned, so pass the generator for those into
                # a routine to derive that.
                TriageString = Triage(cveSummaryForQID['MFL'], cveSummaryForQID['BaseScore'], cveSummaryForQID['Exploit_Known'], 
                        cveSummaryForQID['UserInteraction'], serverIsProduction, CBP, 
                        cveSummaryForQID['Confidentiality'], cveSummaryForQID['Integrity'], cveSummaryForQID['Availability'])

                # Finally, bundle the whole lot together as a dict out output data.
                data_out = dict(finding, **cveSummaryForQID) # concatenates these dicts            

            else: # QID has no matching CVE/CVSS data. Generate triage based off Qualys data. TODO Find correct Algo for this
                # Prepare a dict to look like the CVSS one. Score and vectors are taken from the QID summary
                # UI is presumed to be false, as this data is not available for QID findings (and QID findings tend
                # to be stuff like unpatched software which require no UI anyway)
                fakeCVESummary = {'CVE': '', 'Confidentiality': qidSummary['confidentialityImpact'].upper(), 
                'Integrity': qidSummary['integrityImpact'].upper(), 'Availability': qidSummary['availabilityImpact'].upper(),
                'UserInteraction': False, 'BaseScore': float(qidSummary['baseScore']), 'MFL': False, 'Exploit_Known': False,
                'MFLCVEs': '', 'MFLCount': 0}

                # Prepare a Triage string based upon the QID data as loaded into the fake CVE summary above
                TriageString = Triage(fakeCVESummary['MFL'], fakeCVESummary['BaseScore'], fakeCVESummary['Exploit_Known'], 
                fakeCVESummary['UserInteraction'], serverIsProduction, CBP, 
                fakeCVESummary['Confidentiality'], fakeCVESummary['Integrity'], fakeCVESummary['Availability'])

                # And create the reportLine much as before
                data_out = dict(finding, **fakeCVESummary) # concatenates these dicts
            
            # Add QIDSummary data to the output
            data_out['Patchable'] = qidSummary['Patchable'] # Add the required fields from the QID summary
            data_out['Published_Date'] = qidSummary['Published_Date']
            data_out['VulnerabilityName'] = qidSummary.get('VulnerabilityName') or ''
            data_out['Category'] = qidSummary.get('Category') or ''
            data_out['Solution'] = qidSummary.get('Solution') or ''
            data_out['VendorReferences'] = qidSummary.get('VendorReferences') or ''
            
            # Add the triage string
            data_out['TriagedRating'] = TriageString # Adds the triaged value to the return dict
            
            # Derive the ScanType from the supplied ASSET_TYPE if it is present
            if not 'ASSET_TYPE' in finding or finding['ASSET_TYPE'] is None:
                data_out['ScanType'] = '' # Don't set this if there is no ASSET_TYPE. May change.
            elif finding['ASSET_TYPE'] == 'server':
                data_out['ScanType'] = 'I'# Internal
            elif finding['ASSET_TYPE'] == 'workstation':
                data_out['ScanType'] = 'E'# Endpoint
            else:
                data_out['ScanType'] = '' # Should never be hit, but assures that a value of some sort is returned

            # Add the derived date-based data
            data_out['ReportDate'] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
            data_out['Cycle'] = datetime.datetime.now().strftime('%m %Y')

            firstFoundDate = datetime.datetime.strptime(finding['FIRST_FOUND_DATETIME'], '%Y-%m-%dT%H:%M:%SZ')
            delta = datetime.datetime.now() - firstFoundDate
            data_out['DaysSinceFirstFound'] = delta.days

            if 'High' in TriageString:
                targetRemediationDate = firstFoundDate + timedelta(weeks = 4)
            elif 'Medium' in TriageString:
                targetRemediationDate = firstFoundDate + timedelta(days = 183) # 6 months is a variable time. Pick a good approximation
            else:  # Low
                targetRemediationDate = firstFoundDate + timedelta(days = 365) # as is one year (think leap years). Again, approximate
            data_out['RemediationDue'] = targetRemediationDate.strftime('%Y-%m-%dT%H:%M:%SZ')

            data_out['TargetBreached'] = targetRemediationDate<datetime.datetime.now()
            
            # Other fields
            data_out['Concat'] = finding['ID'] + '-' + finding['VulnID']
                                                                
            # Write out line to temp file (calls json.dumps to write string out)
            temp_file.write_json_line(data_out)

    # finally write out the temp file to the bucket after incorporating the run_date
    preFormat = TARGET_BLOB.replace('%date', '%Y-%m-%d')
    destinationFile = run_date.strftime(preFormat)
    temp_file.save_to_bucket(TARGET_PROJECT, TARGET_BUCKET, destinationFile)

    # No need to explicitly remove the local file. temp_file class has a destructor that will do that.
    temp_file = None
    auditor.completion_time = datetime.datetime.today()
    auditor.log_event()

for run_date in dt.daterange():
    # daterange retrieves the desired range of dates from va_dt_common.common_config.yaml. Leave these dates
    # empty to default to running reports only for today.
    main(run_date)