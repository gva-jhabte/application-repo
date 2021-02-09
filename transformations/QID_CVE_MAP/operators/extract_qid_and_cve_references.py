
from gva.flows import BaseOperator


class ExtractQidAndCveReferences(BaseOperator):

    def execute(self, data, context):
        """
        Interpret each line of data from the file, load into XML and then extract the required data
        """
        QID = data.get('QID')
        CVES = []
        if data.get('CVE_LIST') != None:
            CVE_LIST = data['CVE_LIST']['CVE']
            for CVE in CVE_LIST:
                if str(type(CVE)) == "<class 'str'>":
                    if CVE in ['ID']:
                        CVES.append(CVE_LIST[CVE])
                if str(type(CVE)) == "<class 'collections.OrderedDict'>":
                    for ID in CVE:
                        if ID in ['ID']:
                            CVES.append(CVE[ID])
        for CVE in CVES:
            row = {"QID": QID, "CVE": CVE}
            yield row, context
