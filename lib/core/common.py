# coding:utf-8
from __future__ import print_function
from bs4 import BeautifulSoup
import sys
import string

if sys.version.split()[0].split(".")[0] == 2:
    from urlparse import urlparse  
else :
    from urllib.parse import urlparse
    
import random
import configparser
import requests
import time
import os
import re



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



def url_handle(url):
    """
    url处理函数  

    return:
    dict urldict  
    """

    if url.startswith("http"):
        p = urlparse(url)
        # pass

    else:
        url = "http://" + url 
        p = urlparse(url)
        if ":" in p.netloc:
            if "443" in p.netloc.split(":")[1]:
                url = url.replace("http://","https://")
                p = urlparse(url)

            else:
                pass
        else:
            pass
        

    return p.scheme+"://"+p.netloc

def get_random_ua():
    with open("./data/user_agents.txt","r") as f:
        UAs = [i.strip() for i in f.readlines()]
    return random.choice(UAs)


def random_str(length=10, chars=string.ascii_letters + string.digits):
    return ''.join(random.sample(chars, length))

def get_local_version(path):
    cp = configparser.ConfigParser()
    cp.read(path)
    return cp["info"]["version"]


def get_latest_revision():
    lv = None
    cp = configparser.ConfigParser()
    try:
        req = requests.get("https://raw.githubusercontent.com/bigblackhat/oFx/master/info.ini",timeout = 15)
        cp.read_string(req.text)

        lv = cp["info"]["version"]
    except Exception:
        pass
    return lv



