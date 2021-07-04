# coding:utf-8
from __future__ import print_function
from bs4 import BeautifulSoup
import sys
import string
import argparse
from urllib.parse import urlparse
    
import random
import configparser
import requests
import time
import os
import re

from lib.core.data import vulnoutput,unvulnoutput,unreachoutput,lock,AliveList
from lib.core.log import logverifyerror,logvuln,logunvuln

from requests.exceptions import ConnectTimeout
from requests.exceptions import ConnectionError
from requests.exceptions import HTTPError
from requests.exceptions import TooManyRedirects

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




def run(POC_Class,target,proxy=False,output=True,PocRemain="",Alive_mode = False):

    global vulnoutput,unvulnoutput,unreachoutput,AliveList
    while not target.empty():

        try:
            target_url = target.get()
            rVerify = POC_Class(target_url,proxy)
            poc_name = rVerify._info["name"]
            # print(poc_name)
            vuln = rVerify._verify()
            
            if Alive_mode == True:
                if vuln[0] == True:
                    AliveList.add(target_url)
                    continue
                    # print("yes")
                    
                else:
                    continue
            if vuln[0] == True:
                try:
                    vulntitle=get_title(vuln[1])
                except:
                    vulntitle = ""
                lock.acquire()
                logvuln("POC 剩余 : %s ╭☞ Target 剩余 : %d Vuln %s | WebSite Title：%s "%(PocRemain,target.qsize(),target_url,vulntitle))
                # logvuln("%s ╭☞ %d Vuln %s | WebSite Title：%s | Server Response : %s"%(PocRemain,target.qsize(),target_url,vulntitle,vuln[1]))
                if poc_name in vulnoutput:
                    vulnoutput[poc_name].append(target_url+" || 网站Title： "+vulntitle)
                else:
                    vulnoutput.update({poc_name:list()})
                    vulnoutput[poc_name].append(target_url+" || 网站Title： "+vulntitle)
                lock.release()
            else:
                lock.acquire()
                logunvuln("POC 剩余 : %s ╭☞ Target 剩余 : %d UnVuln %s "%(PocRemain,target.qsize(),target_url))
                unvulnoutput.append(target_url)
                lock.release()
        
        except NotImplementedError as e :
            lock.acquire()
            logverifyerror("POC 剩余 : %s ╭☞ %d The POC does not support virtualized depiction scan mode  Error details：%s "%(PocRemain,target.qsize(),str(e)))
            unreachoutput.append(target_url+" || Error details"+str(e))
            lock.release()
            pass

        except TimeoutError as e:
            lock.acquire()
            logverifyerror("POC 剩余 : %s ╭☞ %d Connection timed out %s Error details：%s "%(PocRemain,target.qsize(),target,str(e)))
            unreachoutput.append(target_url+" || Error details"+str(e))
            lock.release()
            pass

        except HTTPError as e:
            lock.acquire()
            logverifyerror("POC 剩余 : %s ╭☞ %d HTTPError occurred %s Error details：%s "%(PocRemain,target.qsize(),target,str(e)))
            unreachoutput.append(target_url+" || Error details"+str(e))
            lock.release()
            pass

        except ConnectionError as e:
            lock.acquire()
            logverifyerror("POC 剩余 : %s ╭☞ %d Connection error %s Error details：%s "%(PocRemain,target.qsize(),target,str(e)))
            unreachoutput.append(target_url+" || Error details"+str(e))
            lock.release()
            pass

        except TooManyRedirects as e:
            lock.acquire()
            logverifyerror("POC 剩余 : %s ╭☞ %d The number of resets exceeds the limit, and the goal is discarded %s Error details：%s "%(PocRemain,target.qsize(),target,str(e)))
            unreachoutput.append(target_url+" || Error details"+str(e))
            lock.release()
            pass

        except BaseException as e:
            lock.acquire()
            logverifyerror("POC 剩余 : %s ╭☞ %d unknown mistake %s Error details：%s "%(PocRemain,target.qsize(),target,str(e)))
            unreachoutput.append(target_url+" || Error details"+str(e))
            lock.release()
            pass

def GetCommand():
    parser = argparse.ArgumentParser(description="oFx framewark of POC test",
    usage="python3 ofx.py -f [target_path] / -u [url]   -s [poc_path]  --thread 50\n\
       python3 ofx.py --fofa-search")

    searchengine = parser.add_argument_group("SearchEngine")
    searchengine.add_argument("--fofa-search",action="store_true",help="Fofa Search模式，该参数不需要跟值")

    # target = parser.add_argument_group("TARGET")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("-u","--url",type=str,help="指定单个url，该模式不支持多POC或全量POC (e.g. www.baidu.com)")
    target.add_argument("-f","--file",type=str,help="指定存有url列表的文件路径，该模式支持多POC或全量POC (e.g. /root/urllist.txt)")

    script = parser.add_argument_group("Script")
    script.add_argument("-s","--script",type=str,help="指定POC相对路径，格式见readme.md (e.g. -s poc/jellyfin/jellyfin_fileread_scan/poc.py OR -s all)")
    
    system = parser.add_argument_group("System")
    system.add_argument("--thread",default=10,type=int,help="指定线程数，默认为10，仅扫描时指定线程数有效")
    system.add_argument("--proxy",default=False,help="指定Http Proxy，仅扫描时指定线程数有效，Example：127.0.0.1:8080 OR http://127.0.0.1:8080")
    system.add_argument("--output",default=True,help="不用管，扫完了看output目录即可")
    system.add_argument("--version",action="store_true",help="显示本地oFx版本，并根据网络状态给出最新版本号")

    developer = parser.add_argument_group("Developer(POC开发者工具箱)")
    developer.add_argument("--add-poc",action="store_true",help="生成POC标准目录结构，该参数不需要跟值")
    
    if len(sys.argv) == 1:
        sys.argv.append("-h")
    args=parser.parse_args()
    return args 