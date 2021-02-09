# CMDB_GRAPH

Inputs: CMDB_LISTS  
Format: GraphML  
Location: 02_INTERMEDIATE/CMDB_GRAPH/CMDB_GRAPH_%date.graphml

### NODE TYPES

**CI_SERVER**

| Field           | Type         | Description                  |
|-----------------|--------------|------------------------------|
| node_type       | String       | 'ci_server'                  |
| display_name    | String       | Name                         |
| dns_domain      | String       | DNS Domain                   |
| u_sox_control   | String       | SOX Material                 |
| u_environment   | String       | Production or Test           |
| fqdn            | String       | Fully Qualified Domain Name  |


**IP_ADDRESS**

| Field           | Type         | Description               |
|-----------------|--------------|---------------------------|
| node_type       | String       | 'ip_address'              |
| display_name    | String       | IP Address                | 

**SUPPORT_GROUP**

| Field           | Type         | Description               |
|-----------------|--------------|---------------------------|
| node_type       | String       | 'support_group'           |
| display_name    | String       | ----                      |

### EDGES

- CI_SERVER exposes IP_ADDRESS
- IP_ADDRESS exposed by CI_SERVER
- SUPPORT_GROUP supports CI_SERVER
- CI_SERVER supported by SUPPORT_GROUP
