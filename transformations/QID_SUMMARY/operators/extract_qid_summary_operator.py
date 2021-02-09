"""
QID_SUMMARY

Extract summary information for each QID in the QKB file
"""
from gva.flows import BaseOperator
import datetime

# Define some constants and helper methods to interpret CVSS vector strings
# This is a candiate to be put into another library, but so far there is
# only this code

CVSS_DECODER_KEYS = {
    'AV': 'Access Vector',
    'AC': 'Access Complexity',
    'Au': 'Authentication',
    'C': 'confidentialityImpact',
    'I': 'integrityImpact',
    'A': 'availabilityImpact',
    'CVSS': 'CVSS'
}

CVSS_DECODER_IMPACT_VALUES = {
    'N': 'None',
    'P': 'Partial',
    'C': 'Complete'
}

CVSS_IMPACT_KEYS = ('C', 'I', 'A')


def deconstruct_vector_string(vector_string):
    parts = vector_string.split('/')
    dictionary = {(element for element in part.split(':')) for part in parts}
    return dict(dictionary)


def decode_vector_string(vector_string):
    try:
        deconstructed = deconstruct_vector_string(vector_string)
        return {CVSS_DECODER_KEYS[k]: CVSS_DECODER_IMPACT_VALUES[v].upper() for (k, v) in deconstructed.items() if k in CVSS_IMPACT_KEYS}
    except (ValueError, AttributeError):
        return {}


def nullable(value):
    if value == '' or value is None:
        return None
    return value


class ExtractQidSummaryOperator(BaseOperator):

    def _reformat_date(self, in_date: str) -> str:
        if in_date:
            return datetime.datetime.strptime(in_date, "%Y-%m-%dT%H:%M:%SZ").isoformat()
        return None

    def execute(self, data, context):
        QID = data.get('QID')
        PATCHABLE = data.get('PATCHABLE') == '1'
        PUBLISH_DATE = self._reformat_date(data.get('PUBLISHED_DATETIME'))
        VULNERABILITY_NAME = data.get('TITLE')
        CATEGORY = data.get('CATEGORY')
        VENDOR_REFERENCE = data.get('VENDOR_REFERENCE_LIST')
        SOLUTION = data.get('SOLUTION')

        vendor_reference_list = []
        if type(VENDOR_REFERENCE).__name__ == 'OrderedDict':
            references = VENDOR_REFERENCE.get('VENDOR_REFERENCE')
            if not type(references).__name__ == 'list':
                references = [references]
            for reference in references:
                vendor_reference_list.append(reference.get('URL'))

        # extract CVSS information
        CVSS_SCORE = ''
        VECTOR_STRING = ''
        CVSS = data.get('CVSS')
        if CVSS is not None:
            CVSS_SCORE = CVSS.get('BASE')
            VECTOR_STRING = CVSS.get('VECTOR_STRING')

        if type(CVSS_SCORE).__name__ == 'OrderedDict':
            CVSS_SCORE = CVSS_SCORE['#text']

        decoded_vector_string = decode_vector_string(VECTOR_STRING)

        row = {"QID": QID,
               'Patchable': PATCHABLE,
               'Published_Date': PUBLISH_DATE,
               'baseScore': nullable(CVSS_SCORE),
               'vectorString': nullable(VECTOR_STRING),
               'VulnerabilityName': VULNERABILITY_NAME,
               'Category': CATEGORY,
               'VendorReferences': ",".join(vendor_reference_list),
               'Solution': nullable(SOLUTION),
               'availabilityImpact': nullable(decoded_vector_string.get('availabilityImpact')),
               'confidentialityImpact': nullable(decoded_vector_string.get('confidentialityImpact')),
               'integrityImpact': nullable(decoded_vector_string.get('integrityImpact'))
               }
        return row, context
