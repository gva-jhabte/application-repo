"""
Extract QID Summary Operator Tests

Test Cases
1) A valid payload extracts details correctly
2) An invalid payload is handled gracefully
"""
import xmltodict
import sys
import os
import glob
from gva.data.validator import Schema
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from operators import ExtractQidSummaryOperator
try:
    from rich import traceback
    traceback.install()
except ImportError:
    pass


VALID_XML = "<VULN><QID>1</QID><VULN_TYPE>Vulnerability</VULN_TYPE><SEVERITY_LEVEL>1</SEVERITY_LEVEL><TITLE><![CDATA[TITLE]]></TITLE><CATEGORY>Category</CATEGORY><LAST_SERVICE_MODIFICATION_DATETIME>2000-01-01T00:00:00Z</LAST_SERVICE_MODIFICATION_DATETIME><PUBLISHED_DATETIME>2000-01-01T00:00:00Z</PUBLISHED_DATETIME><BUGTRAQ_LIST><BUGTRAQ><ID><![CDATA[XXX]]></ID><URL><![CDATA[http://www.securityfocus.com/bid/XXX]]></URL></BUGTRAQ></BUGTRAQ_LIST><PATCHABLE>1</PATCHABLE><SOFTWARE_LIST><SOFTWARE><PRODUCT><![CDATA[license_software]]></PRODUCT><VENDOR><![CDATA[ca]]></VENDOR></SOFTWARE></SOFTWARE_LIST><CVE_LIST><CVE><ID><![CDATA[CVE-2000-0000]]></ID><URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0000]]></URL></CVE><CVE><ID><![CDATA[CVE-2000-0001]]></ID><URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0001]]></URL></CVE></CVE_LIST><DIAGNOSIS><![CDATA[Diagnosis]]></DIAGNOSIS><CONSEQUENCE><![CDATA[Consequences]]></CONSEQUENCE><SOLUTION><![CDATA[Solution]]></SOLUTION><CORRELATION><EXPLOITS><EXPLT_SRC><SRC_NAME><![CDATA[The Exploit-DB]]></SRC_NAME><EXPLT_LIST><EXPLT><REF><![CDATA[CVE-2000-0000]]></REF><DESC><![CDATA[Description - 0000]]></DESC><LINK><![CDATA[http://www.exploit-db.com/exploits/XXX0]]></LINK></EXPLT><EXPLT><REF><![CDATA[CVE-2000-0001]]></REF><DESC><![CDATA[Description - 0001]]></DESC><LINK><![CDATA[http://www.exploit-db.com/exploits/XXX1]]></LINK></EXPLT></EXPLT_LIST></EXPLT_SRC></EXPLOITS></CORRELATION><CVSS><BASE>10</BASE><TEMPORAL>7.8</TEMPORAL><VECTOR_STRING>CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C</VECTOR_STRING></CVSS><PCI_FLAG>1</PCI_FLAG><DISCOVERY><REMOTE>1</REMOTE><ADDITIONAL_INFO>Patch Available, Exploit Available</ADDITIONAL_INFO></DISCOVERY></VULN>"
INVALID_XML = "<VULN><VULN_TYPE>Vulnerability</VULN_TYPE><SEVERITY_LEVEL>1</SEVERITY_LEVEL><TITLE><![CDATA[TITLE]]></TITLE><CATEGORY>Category</CATEGORY><LAST_SERVICE_MODIFICATION_DATETIME>2000-01-01T00:00:00Z</LAST_SERVICE_MODIFICATION_DATETIME><PUBLISHED_DATETIME></PUBLISHED_DATETIME><BUGTRAQ_LIST><BUGTRAQ><ID><![CDATA[XXX]]></ID><URL><![CDATA[http://www.securityfocus.com/bid/XXX]]></URL></BUGTRAQ></BUGTRAQ_LIST><PATCHABLE>1</PATCHABLE><SOFTWARE_LIST><SOFTWARE><PRODUCT><![CDATA[license_software]]></PRODUCT><VENDOR><![CDATA[ca]]></VENDOR></SOFTWARE></SOFTWARE_LIST><CVE_LIST><CVE><ID><![CDATA[CVE-2000-0000]]></ID><URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0000]]></URL></CVE><CVE><ID><![CDATA[CVE-2000-0001]]></ID><URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0001]]></URL></CVE></CVE_LIST><DIAGNOSIS><![CDATA[Diagnosis]]></DIAGNOSIS><CONSEQUENCE><![CDATA[Consequences]]></CONSEQUENCE><SOLUTION><![CDATA[Solution]]></SOLUTION><CORRELATION><EXPLOITS><EXPLT_SRC><SRC_NAME><![CDATA[The Exploit-DB]]></SRC_NAME><EXPLT_LIST><EXPLT><REF><![CDATA[CVE-2000-0000]]></REF><DESC><![CDATA[Description - 0000]]></DESC><LINK><![CDATA[http://www.exploit-db.com/exploits/XXX0]]></LINK></EXPLT><EXPLT><REF><![CDATA[CVE-2000-0001]]></REF><DESC><![CDATA[Description - 0001]]></DESC><LINK><![CDATA[http://www.exploit-db.com/exploits/XXX1]]></LINK></EXPLT></EXPLT_LIST></EXPLT_SRC></EXPLOITS></CORRELATION><CVSS><BASE>10</BASE><TEMPORAL>7.8</TEMPORAL><VECTOR_STRING>CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C</VECTOR_STRING></CVSS><PCI_FLAG>1</PCI_FLAG><DISCOVERY><REMOTE>1</REMOTE><ADDITIONAL_INFO>Patch Available, Exploit Available</ADDITIONAL_INFO></DISCOVERY></VULN>"


def test_extract_qid_summary_operator_valid_payload():
    """ Test to ensure data is extracted correctly """

    valid_xml = xmltodict.parse(VALID_XML)['VULN']
    extract_qid_summary = ExtractQidSummaryOperator()
    data, context = extract_qid_summary.execute(data=valid_xml, context={})

    assert data.get('QID') == '1'
    assert data.get('Published_Date') == '2000-01-01T00:00:00'
    assert data.get('VulnerabilityName') == 'TITLE'
    assert data.get('confidentialityImpact') == 'COMPLETE'


def test_extract_qid_summary_operator_invalid_payload():
    """ Test should fail invalid payload """

    invalid_xml = xmltodict.parse(INVALID_XML)['VULN']
    extract_qid_summary = ExtractQidSummaryOperator()
    data, context = extract_qid_summary.execute(data=invalid_xml, context={})

    # the field is missing
    assert 'QID' in data and data.get('QID') is None
    # the field is empty
    assert 'Published_Date' in data and data.get('Published_Date') is None
    # the field is all good
    assert data.get('VulnerabilityName') == 'TITLE'


def find_file(filename):
    paths = glob.glob('../../**/' + filename, recursive=True)
    return paths.pop()


def test_extract_qid_summary_operator_validates():
    """ Test the output from the operator complies to the schema """

    valid_xml = xmltodict.parse(VALID_XML)['VULN']
    extract_qid_summary = ExtractQidSummaryOperator()
    data, context = extract_qid_summary(data=valid_xml, context={})

    schema_file = find_file('QID_SUMMARY.metadata')

    validator = Schema(schema_file)
    assert validator.validate(data), validator.last_error


if __name__ == "__main__":
    test_extract_qid_summary_operator_valid_payload()
    test_extract_qid_summary_operator_invalid_payload()
    test_extract_qid_summary_operator_validates()
