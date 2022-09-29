# Detecting the "Manjusaka" C2 framework

Detecting the C2 framework Manjusaka: "A Chinese sibling of Sliver and Cobalt Strike"    


## References: 
Detection logic details:  
https://corelight.com/blog/detecting-manjusaka-c2-framework   
Writeup by Talos:  
https://blog.talosintelligence.com/2022/08/manjusaka-offensive-framework.html  


  
## Suricata:  
Suricata rules are provided here https://github.com/corelight/C2-detection-manjusaka/blob/main/suricata-manjusaka-C2.rules
  
  

## Humio detection:  
```
#path="*http*" method=GET user_agent="Mozilla/*" request_body_len=2 status_code=200 response_body_len=5
```
```
#path="*http*" request_body_len>0 response_body_len>0 uri=*.png NOT resp_mime_types
```
```
#path="*http*" request_body_len>0 response_body_len>0 uri=*.png response_body_len<8 
```
```
#path="*http*" method=GET 
( user_agent="Mozilla/5.0 (Windows NT 8.0; WOW64; rv:58.0) Gecko/20120102 Firefox/58.0" OR user_agent="Mozilla/5.0 (Windows NT 8.0; WOW64; rv:40.0) Gecko")
```
```
#path="*http*" method=GET request_body_len>0 uri="/global/favicon.png"
```
  
  
  
## Splunk detection:  
```
sourcetype="*http*" method=GET user_agent="Mozilla/*" request_body_len=2 status_code=200 response_body_len=5
```
```
sourcetype="*http*" request_body_len>0 response_body_len>0 uri=*.png NOT resp_mime_types
```
```
sourcetype="*http*" request_body_len>0 response_body_len>0 uri=*.png response_body_len<8 
```
```
sourcetype="*http*" method=GET 
( user_agent="Mozilla/5.0 (Windows NT 8.0; WOW64; rv:58.0) Gecko/20120102 Firefox/58.0" OR user_agent="Mozilla/5.0 (Windows NT 8.0; WOW64; rv:40.0) Gecko")
```
```
sourcetype="*http*" method=GET request_body_len>0 uri="/global/favicon.png"
```
  


