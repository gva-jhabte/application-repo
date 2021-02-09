'''
Operator class to produce data for QVM_ALL_REPORT. 

Incoming data for the execute method should be a single row of ASSET_VM data
'''
from gva.flows import BaseOperator
import datetime
from datetime import timedelta

class QVMAllReportOperator(BaseOperator):
    
    
    def __init__(self, CVESummaries, QIDSummaries, CVEsForAllQIDs):
        super().__init__() # Ensure that BaseOperator.__init__ gets called. Note that brackets after super are required.
        
        # Object level variables are created implicitly upon assignment.
        self._CVESummaries = CVESummaries
        self._QIDSummaries = QIDSummaries
        self._CVEsForAllQIDs = CVEsForAllQIDs
    
    def Triage(self, CVEOnMFL, CVSS_score, exploitExists, UIRrequired, ServerIsProduction, serverCBP, 
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

    def CVESummaryForQID(self, CVEsForQID):
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

    def getMaxCBP(self, CBPFromFinding):
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
    
    def execute(self, data, context):
        
        finding = data
        
        # Do some column renames where appropriate to match VSM reporting names
        finding['VulnID'] = finding.pop('QID')
        finding['ScanScore'] = finding.pop('SEVERITY')

        if 'ENVIRONMENT' in finding and not finding['ENVIRONMENT'] is None and finding['ENVIRONMENT'].upper()[:4] == 'PROD':
            serverIsProduction = True
        else:
            serverIsProduction = False

        if 'CBP' in finding:
            CBP = self.getMaxCBP(finding['CBP'])
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
        if finding['VulnID'] in self._QIDSummaries:
            qidSummary = self._QIDSummaries[finding['VulnID']]
            # Some of the equivalents of CVSS data may be missing. Populate with default values in these cases
            if qidSummary['availabilityImpact'] is None:
                qidSummary['availabilityImpact'] = 'NONE'
            if qidSummary['confidentialityImpact'] is None:
                qidSummary['confidentialityImpact'] = 'NONE'
            if qidSummary['integrityImpact'] is None:
                qidSummary['integrityImpact'] = 'NONE'
            if qidSummary['baseScore'] is None:
                qidSummary['baseScore'] = 0
        else:
            # Got a QID with no summary, so build a dummy one. Should really not happen.
            qidSummary = {'QID': finding['VulnID'], 'Patchable': 'Unknown', 'Published_Date': 'Unknown', 'baseScore': 0,
                            'availabilityImpact': 'NONE', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE',
                            'VulnerabilityName': '', 'Category': '', 'Solution': '', 'VendorNotes': ''}

        # Get all the CVEs associated with the finding (may be more than one)
        if finding['VulnID'] in self._CVEsForAllQIDs:
            # Code to generate triage based upon matching CVE data
            CVEIdsForQID = self._CVEsForAllQIDs[finding['VulnID']]

            # Get all the summaries. The odd selector is Dictionary Comprehension syntax and can be read as
            # 'Create a new dictionary (keys:values) based on the keys and values from CVESummaries if the key for
            # an entry in CVESummaries is in CVEsForQID'
            CVESummariesForQID = {k:v for (k, v) in self._CVESummaries.items() if k in CVEIdsForQID}

            # Get a single line rollup of all the CVE data for the QID that can then be used for both triage and return data.
            cveSummaryForQID = self.CVESummaryForQID(CVESummariesForQID)

            # The triage will rely on the highest/worst values for any of the CVEs returned, so pass the generator for those into
            # a routine to derive that.
            TriageString = self.Triage(cveSummaryForQID['MFL'], cveSummaryForQID['BaseScore'], cveSummaryForQID['Exploit_Known'], 
                    cveSummaryForQID['UserInteraction'], serverIsProduction, CBP, 
                    cveSummaryForQID['Confidentiality'], cveSummaryForQID['Integrity'], cveSummaryForQID['Availability'])

            # Finally, bundle the whole lot together as a dict out output data.
            data_out = dict(finding, **cveSummaryForQID) # concatenates these dicts            

        else: # QID has no matching CVE/CVSS data. Generate triage based off Qualys data.
            # Prepare a dict to look like the CVSS one. Score and vectors are taken from the QID summary
            # UI is presumed to be false, as this data is not available for QID findings (and QID findings tend
            # to be stuff like unpatched software which require no UI anyway)
            fakeCVESummary = {'CVE': '', 'Confidentiality': qidSummary['confidentialityImpact'].upper(), 
            'Integrity': qidSummary['integrityImpact'].upper(), 'Availability': qidSummary['availabilityImpact'].upper(),
            'UserInteraction': False, 'BaseScore': float(qidSummary['baseScore']), 'MFL': False, 'Exploit_Known': False,
            'MFLCVEs': '', 'MFLCount': 0}

            # Prepare a Triage string based upon the QID data as loaded into the fake CVE summary above
            TriageString = self.Triage(fakeCVESummary['MFL'], fakeCVESummary['BaseScore'], fakeCVESummary['Exploit_Known'], 
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
        
        # Return the enriched data to the flow
        data = data_out