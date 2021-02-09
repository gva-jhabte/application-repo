# CVE_TWEETS

**Description**: Stream of tweets containing CVE references  
**Source**: https://twitter.com/  
**Classification**: PUBLIC  
**Licence**: UNKNOWN - FAIR USE  

## Fields

| Field           | Type         | Description               |
|-----------------|--------------|---------------------------|
| tweet_id  | numeric   | Globally unique Tweet Identifier |  
| text  | string   | Tweet Body |  
| timestamp  | numeric   | Time of Tweet (Linux Epoch) |  
| user_id  | numeric   | Globally unique User Identifier |  
| user_verified  | boolean   | Is the user verified (blue tick) |  
| user_name  | string   | Name of the user (not-static) |  
| hash_tags  | list   | Hash Tags in the Tweet (limited) |  
| followers  | numeric   | The number of followers the user had at the time of the Tweet |  
| tweets_by_user  | numeric   | The number of tweets published by the user |  
| is_quoting  | [&#39;numeric&#39;, &#39;nullable&#39;]   | The globally unique identifier of the Tweet being quoted, if quoting |  
| is_reply_to  | [&#39;numeric&#39;, &#39;nullable&#39;]   | The globally unique identifier of the Tweet being replied to, if replying |  
| is_retweeting  | [&#39;numeric&#39;, &#39;nullable&#39;]   | The globally unique identifier of the Tweet being retweeted, if retweeting |  
| cves  | list   | The list of CVEs being referenced in the Tweet |  
 

Compressed: False

_this file has been automatically generated - changes may be overridden_