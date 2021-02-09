from gva.flows import BaseOperator
from urllib.request import urlopen
from io import BytesIO
from zipfile import ZipFile


def download_zip(url: str):
    resp = urlopen(url)
    zipfile = ZipFile(BytesIO(resp.read()))
    for file in zipfile.namelist():
        return zipfile.open(file).read()


class AcquireAnnualCveDataOperator(BaseOperator):

    def execute(self, data, context):
        year = context.get('year')
        nvd_url = F'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'
        self.logger.info(F"Downloading NVD CVE data for {year}")
        data = download_zip(nvd_url).decode('utf-8')
        return data, context
