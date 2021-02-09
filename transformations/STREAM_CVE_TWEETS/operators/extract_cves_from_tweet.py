from gva.flows import BaseOperator
import re


class ExtractCvesFromTweetOperator(BaseOperator):

    def find_cves(self, string):
        tokens = re.findall(r"(?i)CVE.\d{4}-\d{4,7}", string)
        result = []
        for token in tokens:
            token = token.upper().strip()
            token = token[:3] + '-' + token[4:]  # snort rules list cves as CVE,2009-0001
            result.append(token)
        return result

    def execute(self, data, context):
        cves = self.find_cves(data.get('text', ''))
        if len(cves) == 0:
            return
        data['cves'] = cves

        return data, context
