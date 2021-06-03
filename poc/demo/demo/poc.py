# coding:utf-8  
import requests
from lib.common import url_handle

_info = {
    "author" : "",                      # POC作者
    "version" : "1",                    # POC版本，默认是1  
    "CreateDate" : "2021-05-18",        # POC创建时间
    "UpdateDate" : "2021-05-18",        # POC创建时间
    "PocDesc" : """
    略  
    """,                                # POC描述，写更新描述，没有就不写

    "name" : "",                        # 漏洞名称
    "AppName" : "",                     # 漏洞应用名称
    "AppVersion" : "",                  # 漏洞应用版本
    "VulnDate" : "",                    # 漏洞公开的时间,不知道就写能查到的最早的文献日期，格式：xxxx-xx-xx
    "VulnDesc" : """
    """,                                # 漏洞简要描述

    "fofa-dork":"",                     # fofa搜索语句
    "example" : "",                     # 存在漏洞的演示url，写一个就可以了
    "exp_img" : ""                      # 先不管
}

def verify(host,proxy):
    """
    返回vuln

    存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

    不存在漏洞：vuln = [False,""]
    """
    vuln = [False,""]
    url = url_handle(host) + "" # url自己按需调整

    if proxy:
        proxies = {
        "http": "http://%s"%(proxy),
        "https": "http://%s"%(proxy),
        }
    try:
        """
        检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
        """
    except Exception as e:
        raise e
    
    return vuln