# coding:utf-8
from bs4 import BeautifulSoup
import urlparse  
import random
def get_title(htmlcode):
    """
    获取网站title  

    use:
    get_title(html_source)  

    return:  
    title  
    """
    soup = BeautifulSoup(htmlcode, 'html.parser')
    return str(soup.title)[7:-8]

# def reip():
#     import re
#     ip ='192.168.1'
#     trueIp =re.search(r'(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])',ip)
#     return trueIp

def url_handle(url):
    """
    url处理函数  

    return:
    dict urldict  
    """
    # 以http开头
        # 放行
    if url.startswith("http"):
        p = urlparse.urlparse(url)
        # pass
    # 否则，默认加http
        # 有端口号
            # 443，改成https
            # 否则，放行
        # 否则，放行
    else:
        url = "http://" + url 
        p = urlparse.urlparse(url)
        if ":" in p.netloc:
            if "443" in p.netloc.split(":")[1]:
                url = url.replace("http://","https://")
                p = urlparse.urlparse(url)

            else:
                pass
        else:
            pass
        
    # url = "http://" + url if not url.startswith("http") else url
    # print p
    return urlparse.urlunsplit([p.scheme, p.netloc, '', '', ''])

def get_random_ua():
    with open("./data/user_agents.txt","r") as f:
        UAs = [i.strip() for i in f.readlines()]
    return random.choice(UAs)
    # pass


if __name__ == "__main__":
    # print url_handle("www.bshine.cn:443")
    # print reip()
    print get_random_ua()