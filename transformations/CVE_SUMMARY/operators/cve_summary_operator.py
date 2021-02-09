'''
Operator class to produce data for CVE_SUMMARY. 

Incoming data for the execute method should be a single row of NVD_CVE_SUMMARY data. This gets enriched by
the MFL data and the Exploit source data (currently ExploitDB, may become ¥)
'''
from gva.flows import BaseOperator
import datetime
from datetime import timedelta

class CVESummaryOperator(BaseOperator):
    
    def __init__(self, MFLs, Exploits):
        super().__init__()
        
        self._MFLs = MFLs
        self._Exploits = Exploits
    
    def execute(self, data, context):

        result = {}
        result['CVE'] = data.get('CVE')

        # Default to using the CVSSv2 scoring system, as it is less severe than CVSSv3 and will therefore
        # result in a narrower range of vulns that need addressing purely from CVSS scores when triaged,
        # which in turn allows the business to focus on remediation better. 
        # Each item checked individualloy to guard against isolated items being missed from the incoming data
        if 'v2.0:baseScore' in data and data['v2.0:baseScore'] is not None:
            result['BaseScore'] = data['v2.0:baseScore']
        elif 'v3.0:baseScore' in data and data['v3.0:baseScore'] is not None:
            result['BaseScore'] = data['v3.0:baseScore']
        else:
            result['BaseScore'] = None
            
        if 'v2.0:userInteractionRequired' in data and data['v2.0:userInteractionRequired'] is not None:
            result['UserInteraction'] = data['v2.0:userInteractionRequired']
        elif 'v3.0:userInteractionRequired' in data and data['v3.0:userInteractionRequired'] is not None:
            result['UserInteraction'] = data['v3.0:userInteractionRequired']
        else:
            result['UserInteraction'] = None
            
        if 'v2.0:confidentialityImpact' in data and data['v2.0:confidentialityImpact'] is not None:
            result['Confidentiality'] = data['v2.0:confidentialityImpact']
        elif 'v3.0:confidentialityImpact' in data and data['v3.0:confidentialityImpact'] is not None:
            result['Confidentiality'] = data['v3.0:confidentialityImpact']
        else:
            result['Confidentiality'] = None
            
        if 'v2.0:integrityImpact' in data and data['v2.0:integrityImpact'] is not None:
            result['Integrity'] = data['v2.0:integrityImpact']
        elif 'v3.0:integrityImpact' in data and data['v3.0:integrityImpact'] is not None:
            result['Integrity'] = data['v3.0:integrityImpact']
        else:
            result['Integrity'] = None
            
        if 'v2.0:availabilityImpact' in data and data['v2.0:availabilityImpact'] is not None:
            result['Availability'] = data['v2.0:availabilityImpact']
        elif 'v3.0:availabilityImpact' in data and data['v3.0:availabilityImpact'] is not None:
            result['Availability'] = data['v3.0:availabilityImpact']
        else:
            result['Availability'] = None

        # Enrich with booleans indicating whether the CVE in question is on the MFL or the known Exploit list
        result['MFL'] = result['CVE'] in self._MFLs
        result['Exploit_Known'] = result['CVE'] in self._Exploits

        # return the enriched data to the flow
        return result, context