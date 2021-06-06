# coding:utf-8
from bs4 import BeautifulSoup
import urlparse  
import random
import configparser
import requests
import sys
import time
import os
import subprocess
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

def get_local_version(path):
    cp = configparser.ConfigParser()
    cp.read(path)
    return cp["info"]["version"]


def get_latest_revision():
    lv = None
    cp = configparser.ConfigParser()
    try:
        req = requests.get("https://raw.githubusercontent.com/bigblackhat/oFx/master/info.ini")
        cp.read_string(req.text)

        lv = cp["info"]["version"]
    except Exception:
        pass
    return lv


# def data_to_stdout(data, bold=False):
#     """
#     Writes text to the stdout (console) stream
#     """
    
#     message = ""

#     if isinstance(data, str):
#         message = stdout_encode(data)
#     else:
#         message = data

#     sys.stdout.write(set_color(message, bold))

#     try:
#         sys.stdout.flush()
#     except IOError:
#         pass
#     return

def poll_process(process, suppress_errors=False):
    """
    Checks for process status (prints . if still running)
    """

    while True:
        # data_to_stdout(".")
        time.sleep(1)

        return_code = process.poll()

        if return_code is not None:
            if not suppress_errors:
                pass
                # if return_code == 0:
                #     data_to_stdout(" done\n")
                # elif return_code < 0:
                #     data_to_stdout(" process terminated by signal {}\n".format(return_code))
                # elif return_code > 0:
                #     data_to_stdout(" quit unexpectedly with return code {}\n".format(return_code))

            break

def stdout_encode(data):
    """
    Cross-linked function
    """
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    else:
        data = str(data)
    return data

def get_revision_number():
    """
    Returns abbreviated commit hash number as retrieved with "git rev-parse --short HEAD"
    """

    ret = None
    file_path = None
    _ = os.path.dirname(__file__)

    while True:
        file_path = os.path.join(_, ".git", "HEAD")
        if os.path.exists(file_path):
            break
        else:
            file_path = None
            if _ == os.path.dirname(_):
                break
            else:
                _ = os.path.dirname(_)

    while True:
        if file_path and os.path.isfile(file_path):
            with open(file_path, "r") as f:
                content = f.read()
                file_path = None
                if content.startswith("ref: "):
                    file_path = os.path.join(_, ".git", content.replace("ref: ", "")).strip()
                else:
                    match = re.match(r"(?i)[0-9a-f]{32}", content)
                    ret = match.group(0) if match else None
                    break
        else:
            break

    if not ret:
        process = subprocess.Popen("git rev-parse --verify HEAD",
                                   shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, _ = process.communicate()
        stdout = stdout_encode(stdout)
        match = re.search(r"(?i)[0-9a-f]{32}", stdout or "")
        ret = match.group(0) if match else None

    return ret[:7] if ret else None


if __name__ == "__main__":
    # print url_handle("www.bshine.cn:443")
    # print reip()
    print get_random_ua()