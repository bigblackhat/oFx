# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class POC(POCBase):
    
    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-03",        # POC创建时间
        "UpdateDate" : "2021-06-03",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "url存活检测",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "各类web应用",           # 漏洞应用名称
        "AppVersion" : "",                  # 受漏洞影响的应用版本
        "VulnDate" : "2021-06-03",                    # 漏洞公开的时间,不知道就写能查到的最早的文献日期，格式：xxxx-xx-xx
        "VulnDesc" : """
        略
        """,                                # 漏洞简要描述

        "fofa-dork":"略",                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管

    }

    timeout = 10

    def _verify(self):
        vuln = [False,""]
        url = self.target  # url自己按需调整

        # proxies = None
        

        headers = {"User-Agent":get_random_ua(),}
        try:
            req = requests.get(url,headers = headers,proxies = self.proxy,verify=False,timeout = self.timeout)  

            if str(req.status_code)[0] == "1" or \
                str(req.status_code)[0] == "2" or \
                    str(req.status_code)[0] == "3" or \
                        str(req.status_code)[0] == "4" or \
                            str(req.status_code)[0] == "5":
                vuln = [True,req.text]
        except Exception as e:
            raise e
        
        return vuln

    def _attack(self):
        return self._verify()