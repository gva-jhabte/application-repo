"""
Test CVE Extractor

Test that the CVE extractor finds all the CVEs
"""
import sys
import os
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from operators import ExtractCvesFromTextOperator
try:
    from rich import traceback
    traceback.install()
except ImportError:
    pass


# multiple CVEs
# no CVEs
# CVE surrounded by quotes
# invalid CVE format
# invalid CVE format
# just a CVE on a line

PAYLOAD = "cve-2020-09123,cve-1002-12039\n" + \
            "no cves\n" + \
            "in quotes 'CVE-2020-0144' " + \
            "not valid cve-1000-1234567890" + \
            "CVE-200-0000" + \
            "CVE-2017-0144"


def test_cve_split_operator():

    op = ExtractCvesFromTextOperator()
    result = op(data=PAYLOAD)

    # we need to enumerate the generator to get the data fields
    data = []
    for d, c in result:
        data.append(d)

    assert len(data) == 4
    assert data[0] == {'CVE': 'CVE-2020-09123'}
    assert data[1] == {'CVE': 'CVE-1002-12039'}
    assert data[2] == {'CVE': 'CVE-2020-0144'}
    assert data[3] == {'CVE': 'CVE-2017-0144'}


if __name__ == "__main__":
    test_cve_split_operator()
