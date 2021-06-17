# coding:utf-8  
import redis
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    def __init__(self, host, proxy=None):
        if host.startswith("redis://"):
            self.target = host[8:]
        else:
            self.target = host
        
        self.proxy = None

        self.timeout = 10


    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
        出于专注与web领域的考虑，本POC仅简单支持检测redis未授权访问而已,
        另外，redis连接比较慢，扫起来会比http要久很多，扫之前做好心理准备
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Redis未授权访问",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Redis",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
        
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        app="redis"
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
        redis_host = self.target.split(":")[0]  # url自己按需调整
        redis_port = self.target.split(":")[1]

        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            r = redis.Redis(redis_host, port=redis_port, db=0, socket_timeout=6.0)
            if r.ping() is True:
                vuln = [True,"connect success"]
            else:
                vuln = [False,"connect field"]
        except Exception as e:
            raise e

        
        return vuln

    def _attack(self):
        return self._verify()