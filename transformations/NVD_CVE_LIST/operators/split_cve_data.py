from gva.flows import BaseOperator
from gva.utils.json import parse


class SplitCveDataOperator(BaseOperator):

    def execute(self, data, context):
        json_block = parse(str(data))
        for json_record in json_block['CVE_Items']:
            yield json_record, context
