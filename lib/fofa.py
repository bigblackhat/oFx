# coding:utf-8
import requests
import configparser
from base64 import b64encode

def get_ukey(cfg_path):
    cp = configparser.ConfigParser()
    cp.read(cfg_path)
    return [cp["Fofa"]["user"],cp["Fofa"]["key"]]

def fofa_login(user,key):
    _login = False
    try:
        # print "https://fofa.so/api/v1/info/my?email={user}&key={key}".format(user = user,key = key)
        req = requests.get("https://fofa.so/api/v1/info/my?email={user}&key={key}".format(user = user,key = key))
        if req and req.status_code == 200 and "username" in req.json():
            _login =  True
        else:
            while _login == False:
                err_msg = "登陆失败，请重新确认并在下方输入user和key"
                print err_msg
                user = raw_input("Fofa 账号：")
                key = raw_input("Fofa key：")
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
    for i in range(1,page+1):
        url = "https://fofa.so/api/v1/search/all?email={user}&key={key}&qbase64={dork}&fields={resource}&page={page}".format(
                        user=user, key=key, dork=b64encode(dork.encode()).decode(), resource=resource, page=i)
        req = requests.get(url,timeout=80)
        if req and req.status_code == 200 and "results" in req.json():
            content = req.json()
            # print len(content['results'])
            for match in content['results']:
                search_result.append(match)
            print "第{page}页获取成功".format(page = i)
        else:
            print "[PLUGIN] Fofa:{}".format(req.text)
            continue

    # print len(search_result)
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

