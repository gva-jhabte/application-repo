from gva.flows import BaseOperator
import re


def find_cves(string):
    tokens = re.findall(r"(?i)CVE.\d{4}-\d{4,7}\b", string)
    for token in tokens:
        token = token.upper().strip()
        token = token[:3] + '-' + token[4:]  # snort rules list cves as CVE,2009-0001
        yield {'CVE': token}


class ExtractCvesFromTextOperator(BaseOperator):

    def execute(self, data, context):
        lines = data.split()
        for line in lines:
            for cve in find_cves(line):
                yield cve, context
