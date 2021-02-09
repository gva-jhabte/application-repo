from gva.flows import BaseOperator
import datetime


class ExtractCveDetailsOperator(BaseOperator):

    def _reformat_date(self, in_date: str) -> str:
        if in_date:
            return datetime.datetime.strptime(in_date, "%Y-%m-%dT%H:%MZ").isoformat()
        return None

    def execute(self, data, context):
        """
        Interpret each line of data from the file, load into JSON and then extract the required data
        """
        result = {}

        result['CVE'] = data['cve']['CVE_data_meta']['ID']
        result['publishedDate'] = self._reformat_date(data['publishedDate'])
        try:
            result['CWE'] = data['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
        except (KeyError, IndexError):
            result['CWE'] = ''
        result['Description'] = data['cve']['description']['description_data'][0]['value']

        if data['impact'].get('baseMetricV3'):
            base = data['impact']['baseMetricV3']['cvssV3']
            result['v3.0:vectorString'] = base.get('vectorString')
            result['v3.0:attackVector'] = base.get('attackVector')
            result['v3.0:attackComplexity'] = base.get('attackComplexity')
            result['v3.0:privilegesRequired'] = base.get('privilegesRequired')
            result['v3.0:userInteraction'] = base.get('userInteraction')
            result['v3.0:scope'] = base.get('scope')
            result['v3.0:confidentialityImpact'] = base.get('confidentialityImpact').upper()
            result['v3.0:integrityImpact'] = base.get('integrityImpact').upper()
            result['v3.0:availabilityImpact'] = base.get('availabilityImpact').upper()
            result['v3.0:baseScore'] = base.get('baseScore')
            result['v3.0:baseSeverity'] = base.get('baseSeverity')
            result['v3.0:exploitabilityScore'] = data['impact']['baseMetricV3'].get('exploitabilityScore')
            result['v3.0:impactScore'] = data['impact']['baseMetricV3'].get('impactScore')

        if data['impact'].get('baseMetricV2'):
            base = data['impact']['baseMetricV2']['cvssV2']
            result['v2.0:vectorString'] = base.get('vectorString')
            result['v2.0:accessVector'] = base.get('accessVector')
            result['v2.0:accessComplexity'] = base.get('accessComplexity')
            result['v2.0:authentication'] = base.get('authentication')
            result['v2.0:confidentialityImpact'] = base.get('confidentialityImpact').upper()
            result['v2.0:integrityImpact'] = base.get('integrityImpact').upper()
            result['v2.0:availabilityImpact'] = base.get('availabilityImpact').upper()
            result['v2.0:baseScore'] = base.get('baseScore')
            result['v2.0:userInteractionRequired'] = data['impact']['baseMetricV2'].get('userInteractionRequired')
            result['v2.0:exploitabilityScore'] = data['impact']['baseMetricV2'].get('exploitabilityScore')
            result['v2.0:impactScore'] = data['impact']['baseMetricV2'].get('impactScore')

        return result, context
