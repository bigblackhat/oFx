# coding:utf-8
from bs4 import BeautifulSoup
import urlparse  

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
    url = "http://" + url if not url.startswith("http") else url
    p = urlparse.urlparse(url)
    return urlparse.urlunsplit([p.scheme, p.netloc, '', '', ''])

if __name__ == "__main__":
    print url_handle("www.bshine.cn")
    # print reip()