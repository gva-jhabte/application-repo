# QVM_FINDINGS

**Description**: Set of Qualys VM scan findings reported per asset  
**Source**: https://www.qualys.com/  
**Classification**: CONFIDENTIAL  
**Licence**: UNKNOWN  

## Fields

| Field           | Type         | Description               |
|-----------------|--------------|---------------------------|
| QID  | numeric   | Qualys finding type identifier |  
| TYPE  | string  [&#39;Confirmed&#39;, &#39;Potential&#39;] |  |  
| SEVERITY  | numeric 0 5 |  |  
| SSL  | boolean   |  |  
| RESULTS  | [&#39;string&#39;, &#39;nullable&#39;]   |  |  
| STATUS  | enum  [&#39;Active&#39;, &#39;New&#39;, &#39;Re-Opened&#39;] |  |  
| FIRST_FOUND_DATETIME  | date   |  |  
| LAST_FOUND_DATETIME  | date   |  |  
| TIMES_FOUND  | numeric   |  |  
| LAST_TEST_DATETIME  | date   |  |  
| LAST_UPDATE_DATETIME  | date   |  |  
| IS_IGNORED  | boolean   |  |  
| IS_DISABLED  | boolean   |  |  
| LAST_PROCESSED_DATETIME  | date   |  |  
| PORT  | [&#39;numeric&#39;, &#39;nullable&#39;]   |  |  
| ID  | numeric   |  |  
| IP  | string   |  |  
| QUALYS_OS  | [&#39;string&#39;, &#39;nullable&#39;]   |  |  
| DNS  | [&#39;string&#39;, &#39;nullable&#39;]   |  |  
| NETBIOS  | [&#39;string&#39;, &#39;nullable&#39;]   |  |  
| LAST_SCAN_DATETIME  | date   |  |  
| LAST_VM_SCANNED_DATE  | date   |  |  
| LAST_VM_SCANNED_DURATION  | numeric   |  |  
| LAST_VM_AUTH_SCANNED_DATE  | [&#39;date&#39;, &#39;nullable&#39;]   |  |  
 

Compressed: True

_this file has been automatically generated - changes may be overridden_