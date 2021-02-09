# QID_SUMMARY

**Description**: Summary information per Qualys finding type, uniquely identified by the QID. Sourced from the Qualys KnowledgeBase  
**Source**: https://www.qualys.com/  
**Classification**: PUBLIC  
**Licence**: UNKNOWN  

## Fields

| Field           | Type         | Description               |
|-----------------|--------------|---------------------------|
| QID  | numeric   | Qualys finding type identifier |  
| Patchable  | boolean   |  |  
| Published_Date  | date   | QID publish date |  
| baseScore  | [&#39;numeric&#39;, &#39;nullable&#39;] 0 10 | Number between 0 and 10, correlating to anticipated severity of finding |  
| vectorString  | [&#39;string&#39;, &#39;nullable&#39;]   | Encoded view of factors which contribute to the baseScore |  
| VulnerabilityName  | string   | Short title for the finding type |  
| Category  | string   | Qualys category (unknown purpose) |  
| VendorReferences  | [&#39;string&#39;, &#39;nullable&#39;]   | Locations of additional information about the finding |  
| Solution  | [&#39;string&#39;, &#39;nullable&#39;]   | Description of activities to rememdiate finding |  
| availabilityImpact  | [&#39;enum&#39;, &#39;nullable&#39;]  [&#39;NONE&#39;, &#39;PARTIAL&#39;, &#39;COMPLETE&#39;] | CVSS style impact rating for availability |  
| confidentialityImpact  | [&#39;enum&#39;, &#39;nullable&#39;]  [&#39;NONE&#39;, &#39;PARTIAL&#39;, &#39;COMPLETE&#39;] | CVSS style impact rating for availability |  
| integrityImpact  | [&#39;enum&#39;, &#39;nullable&#39;]  [&#39;NONE&#39;, &#39;PARTIAL&#39;, &#39;COMPLETE&#39;] | CVSS style impact rating for availability |  
 

Compressed: True

_this file has been automatically generated - changes may be overridden_