import configparser
import random
import string
import time
from json import JSONDecodeError

import requests

from lib.core import root_path
from lib.core.common import random_str


class dnslog:
    def __init__(self):
        type = ""  # ceye.io ,dnslog.cn
        self.dnsplat_obj = ""

    def get_dnslog(self):

        self.type = "dnslog.cn"

        if self.type == "ceye.io":
            self.dnsplat_obj = CeyeApi()
            dns_domain = random_str() + "." + self.dnsplat_obj.new_domain()
        elif self.type == "dnslog.cn":
            self.dnsplat_obj = DnsLogApi()
            dns_domain = random_str() + "." + self.dnsplat_obj.new_domain()
        return dns_domain

    def check_dnslog(self, flag):
        return self.dnsplat_obj.check(flag)

    def get_all_log(self):
        return self.dnsplat_obj.get_all_log()


class DnsLogApi(object):

    def __init__(self):
        self.req = requests.Session()
        self._new_api = "http://www.dnslog.cn/getdomain.php?t=0."  # + random_str(10, string.digits)
        self._check_api = "http://www.dnslog.cn/getrecords.php?t=0."  # + random_str(10, string.digits)
        self.sleep = 10

    def new_domain(self) -> str:
        '''
        返回dns域名
        :return:
        '''
        try:
            resp = self.req.get(self._new_api).text
        except:
            resp = ''
        return resp

    def get_all_log(self):
        time.sleep(random.randint(10, 15))
        try:
            resp = self.req.get(self._check_api).json()
            log_list = []
            for i in resp:
                log_list.append(i[0])
        except JSONDecodeError:
            log_list = []
        return log_list

    def check(self, flag):
        all_log = self.get_all_log()
        for i in all_log:
            if flag.lower() in i.lower():
                return True


class CeyeApi(object):
    def __init__(self):
        self.token = ""
        self.subdomain = ""

    def new_domain(self):

        cp = configparser.ConfigParser()
        cp.read(root_path + "/lib/ceye.ini")
        self.subdomain = cp["ceye"]["dns"]
        self.token = cp["ceye"]["token"]

        return self.subdomain

    def check(self, flag):
        time.sleep(random.randint(10, 15))
        api_url = "http://api.ceye.io/v1/records?token=" + self.token + "&type=dns"

        req = requests.get(api_url, timeout=50)
        if "User Not Exists" in req.text:
            return "<title>ceye 配置错误，无法获取数据</title>"
        elif flag.lower() in req.text.lower():
            return True
        else:
            return False

    def get_all_log(self):
        time.sleep(random.randint(10, 15))
        api_url = "http://api.ceye.io/v1/records?token=" + self.token + "&type=dns"

        req = requests.get(api_url, timeout=50)
        return req.text


if __name__ == "__main__":
    # dnsflag = CeyeApi()
    # subdomain = dnsflag.new_domain()
    # check = dnsflag.check("dd.ky7ir4.ceye.io")
    # list = dnsflag.get_all_log()
    # for i in list:
    #     if "dd.ky7ir4.ceye.io".lower() in i.lower():
    #         print("成功")

    dnsflag = dnslog()
    subdomain = dnsflag.get_dnslog()
    test = input("test domain: ")
    check = dnsflag.check_dnslog(test)
    list = dnsflag.get_all_log()
    for i in list:
        if test.lower() in i.lower():
            print("成功")
