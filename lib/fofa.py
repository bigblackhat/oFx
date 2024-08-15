# coding:utf-8
from __future__ import print_function

import time

import requests
import configparser
from base64 import b64encode
import base64
import json
import sys
from lib.core.common import create_file, append_file, delete_file, read_file,clear_file

from lib.core.log import loglogo, logcritical

if sys.version.split()[0].split(".")[0] == 2:
    reload(sys)
    sys.setdefaultencoding("utf-8")


def get_ukey(cfg_path):
    cp = configparser.ConfigParser()
    cp.read(cfg_path)
    return [cp["Fofa"]["user"], cp["Fofa"]["key"]]


def fofa_login(user, key):
    _login = False
    try:
        # print "https://fofa.so/api/v1/info/my?email={user}&key={key}".format(user = user,key = key)
        req = requests.get("https://fofa.info/api/v1/info/my?email={user}&key={key}".format(user=user, key=key))
        if req and req.status_code == 200 and "username" in req.json():
            _login = True
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
                _login = fofa_login(user, key)[0]
    except KeyboardInterrupt:
        exit("\nUser exit")
    return [True, user, key]


def ukey_save(user, key, save_path):
    cp = configparser.ConfigParser()
    cp.add_section("Fofa")
    cp["Fofa"]["user"] = user
    cp["Fofa"]["key"] = key
    cp.write(open(save_path, "w"))


def adaptive_get_dork(user, key, dork, pass_china=False):
    all_dork = []

    if "country" in dork or "region" in dork:
        nodes = [i.strip() for i in dork.split("&&")]
        dork = ""
        for i in nodes:
            if "country" in i or "region" in i:
                continue
            else:
                dork += i + " && "
        dork = dork.strip(" &&")

    dork_b64 = b64encode(dork.encode()).decode()

    loglogo("开始自适应模块")
    api = "https://fofa.info/api/v1/search/stats?fields=country&qbase64={dork}&email={user}&key={key}".format(
        dork=dork_b64, user=user, key=key)
    req = requests.get(api, timeout=80)

    json_object = json.loads(req.text)
    top5 = json_object["aggs"]["countries"]
    for i in top5:
        country = i["name_code"]
        if country == "CN" and pass_china:
            continue
        if i["regions"] == None:
            loglogo(f"自适应修改行政区划搜索范围：country={country}")
            all_dork.append(f"{dork} && country=\"{country}\"")
            continue
        for r in i["regions"]:
            region = "" if r["name"] == "Unknown" else r["name"]
            loglogo(f"自适应修改行政区划搜索范围：country={country} && region={region}")
            new_dork = dork + " && country = \"{country}\" && region = \"{region}\"".format(country=country,
                                                                                            region=region)
            all_dork.append(new_dork)

    loglogo("自适应dork生成完毕，开始对接Fofa Api获取相应资产")
    return all_dork


def get_asset(user, key, dork, page):
    result = []
    resource = 'protocol,ip,port,host'
    url = "https://fofa.info/api/v1/search/all?email={user}&key={key}&qbase64={dork}&fields={resource}&page={page}".format(
        user=user, key=key, dork=b64encode(dork.encode()).decode(), resource=resource, page=page)
    req = requests.get(url, timeout=80)

    # 返回结果为空
    if "\"results\":[],\"size\":0" in req.text:
        return False
    # 语法错误
    elif "\"errmsg\":\"query statement error\",\"error\":true" in req.text:
        return False
    # 已无更多搜索结果
    elif "\"results\":[]" in req.text:
        return False
    # 正常情况下
    elif req and req.status_code == 200 and "results" in req.json():
        content = req.json()
        # print len(content['results'])
        for match in content['results']:
            result.append(match)
        loglogo("第{page}页获取成功".format(page=page))
    else:
        print("[PLUGIN] Fofa:{}".format(req.text))
        return True

    return_list = []
    for i in result:
        if i[3] != "":  # 优先考虑protocol➕host的模式
            if "http://" in i[3] or "https://" in i[3]:
                url = i[3]
            elif "443" in i[2]:  # 部分host字段没有带协议，需要自己加
                url = "https://" + i[3]
            else:
                url = "http://" + i[3]
        else:  # protocol➕ip➕port 作为兜底
            if i[0] != "":
                url = i[0] + "://" + i[1] + ":" + i[2]
            elif "443" in i[2]:
                url = "https://" + i[1] + ":" + i[2]
            else:
                url = "http://" + i[1] + ":" + i[2]
        return_list.append(url)
    return return_list


def get_assets(user, key, dork, path):
    search_result = []
    page = 100
    # dork = str(base64.b64decode(dork),encoding = "utf-8")
    for i in range(1, page + 1):
        asset = get_asset(user, key, dork, page=i)
        if asset == False:
            break
        elif asset == True:
            continue
        else:
            for i in asset:
                append_file(path, content=f"{i}\n")

        time.sleep(1)
    return search_result


def fofa_search(user, key, dork, search_modle, pass_china, save_path):
    # print "in search"
    url_list = list()
    create_file(save_path)

    china_regions = ["Beijing", "Zhejiang", "Guangdong", "Sichuan",
                     "Shanghai", "Jiangsu", "Fujian", "Shandong",
                     "Hubei", "Shanxi", "Shaanxi", "Chongqing",
                     "Hunan", "Henan", "Liaoning", "Anhui",
                     "Guangxi Zhuangzu", "Hebei", "Jiangxi", "Tianjing",
                     "Xinjiang Uygur", "Ningxia Huizu", "Jilin", "Yunnan",
                     "Nei Mongol", "Heilongjiang", "Hainan", "Gansu",
                     "Guizhou","Qinghai", "Xizang"
                     ]
    if search_modle == 2:
        all_dork = adaptive_get_dork(user, key, dork, pass_china)
    elif search_modle == 3:
        all_dork = [f"{dork} && country=\"CN\" && region=\"{i}\"" for i in china_regions]
    else:
        all_dork = [dork]

    for i in all_dork:
        loglogo("目标国家/地区：{country}，行政区划：{region}".format(country=i.split("&&")[-2].strip().split("=")[1],
                                                                   region=i.split("&&")[-1].strip().split("=")[
                                                                       1])) if len(
            all_dork) > 1 else ""
        get_assets(user=user, key=key, dork=i, path=save_path)

    # if len(search_result) == 0:
    #     err_msg = "\033[31m"
    #     err_msg += "搜索语句{dork}无任何返回结果，疑似存在语法错误\n请前往fofa web端测试搜索语句的有效性"
    #     err_msg += "\033[0m"
    #     delete_file(save_path)
    #     exit(err_msg.format(dork=dork, ))

    search_result = read_file(save_path).split("\n")
    for i in search_result:
        i = i.strip()
        if len(i)==0:
            continue
        url_list.append(i)

    url_list = set(url_list)

    clear_file(path=save_path)
    for i in url_list:
        append_file(save_path,content=f"{i}\n")
    return len(url_list)


if __name__ == "__main__":
    gen_search_all("", "", dork="app=\"ATLASSIAN-Confluence\"")
