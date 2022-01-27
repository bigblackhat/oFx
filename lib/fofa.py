# coding:utf-8
from __future__ import print_function
import requests
import configparser
from base64 import b64encode
import base64

import sys

from lib.core.log import loglogo,logcritical

if sys.version.split()[0].split(".")[0] == 2:
    reload(sys)
    sys.setdefaultencoding("utf-8")

def get_ukey(cfg_path):
    cp = configparser.ConfigParser()
    cp.read(cfg_path)
    return [cp["Fofa"]["user"],cp["Fofa"]["key"]]

def fofa_login(user,key):
    _login = False
    try:
        # print "https://fofa.so/api/v1/info/my?email={user}&key={key}".format(user = user,key = key)
        req = requests.get("https://fofa.info/api/v1/info/my?email={user}&key={key}".format(user = user,key = key))
        if req and req.status_code == 200 and "username" in req.json():
            _login =  True
        else:
            while _login == False:
                err_msg = "登陆失败，请重新确认并在下方输入user和key"
                logcritical(err_msg)
                if sys.version.split()[0].split(".")[0] == 2:
                    user = raw_input("Fofa 账号：")
                    key = raw_input("Fofa key：")
                else:
                    user = input("Fofa 账号：")
                    key = input("Fofa key：")
                # print user,key
                _login = fofa_login(user,key)[0]
    except KeyboardInterrupt:
        exit("\nUser exit")
    return [True,user,key]

def ukey_save(user,key,save_path):
    cp = configparser.ConfigParser()
    cp.add_section("Fofa")
    cp["Fofa"]["user"] = user
    cp["Fofa"]["key"] = key
    cp.write(open(save_path,"w"))

def fofa_search(user,key,dork,save_path):
    # print "in search"
    search_result = list()
    url_list = list()
    resource = 'protocol,ip,port'
    page = 100
    # dork = str(base64.b64decode(dork),encoding = "utf-8")
    for i in range(1,page+1):
        url = "https://fofa.info/api/v1/search/all?email={user}&key={key}&qbase64={dork}&fields={resource}&page={page}".format(
                        user=user, key=key, dork=b64encode(dork.encode()).decode(), resource=resource, page=i)
        req = requests.get(url,timeout=80)
        # 返回结果为空
        if "\"results\":[],\"size\":0" in req.text:
            err_msg = "\033[31m"
            err_msg += "搜索语句{dork}无任何返回结果\n请前往fofa web端测试搜索语句的有效性"
            err_msg += "\033[0m"
            exit(err_msg.format(dork=dork,))
            # break
        # 语法错误
        elif "\"errmsg\":\"query statement error\",\"error\":true" in req.text:
            print("[PLUGIN] Fofa:{}".format(req.text))
            err_msg = "\033[31m"
            err_msg += "搜索语句{dork}疑似存在语法错误\n请前往fofa web端测试搜索语句的有效性"
            err_msg += "\033[0m"
            exit(err_msg.format(dork=dork,))
        elif "\"results\":[]," in req.text:
            err_msg = "\n\033[35m"
            err_msg += "已无更多搜索结果\n开始保存文件"
            err_msg += "\033[0m"
            logcritical(err_msg)
            break
        # 正常情况下
        elif req and req.status_code == 200 and "results" in req.json():
            content = req.json()
            # print len(content['results'])
            for match in content['results']:
                search_result.append(match)
            loglogo("第{page}页获取成功".format(page = i))
        else:
            print("[PLUGIN] Fofa:{}".format(req.text))
            continue

    for i in search_result:
        if i[0] != "":
            url = i[0]+"://"+i[1]+":"+i[2]
        elif "443" in i[2]:
            url = "https://" + i[1] + ":" + i[2]
        else:
            url = "http://" + i[1] + ":" + i[2]
        url_list.append(url)
    # print len(url_list)
    url_list = set(url_list)
    # print len(url_list)
    with open(save_path,"w") as f:
        for i in url_list:
            f.write(i+"\n")
    return len(url_list)

