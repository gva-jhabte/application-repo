"""
Test NVE CVE Splitters

Test that the splitter return the right number of records
"""
import sys
import os
import json
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from operators import SplitCveDataOperator
try:
    from rich import traceback
    traceback.install()
except ImportError:
    pass


PAYLOAD = {
    "not_read": "not read",
    "CVE_Items": [
        {"item": 1},
        {"item": 2},
        {"item": 3}
    ]
}


def test_cve_split_operator():

    op = SplitCveDataOperator()
    payload = json.dumps(PAYLOAD)
    result = op(data=payload)

    # we need to enumerate the generator to get the data fields
    data = []
    for d, c in result:
        data.append(d)

    assert len(data) == 3


if __name__ == "__main__":
    test_cve_split_operator()
