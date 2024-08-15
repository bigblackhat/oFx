# coding:utf-8
import time
from urllib import request
import ssl
import chardet
from lib.core.common import url_handle, get_random_ua, gen_title
from lib.core.poc import POCBase

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class POC(POCBase):
    _info = {
        "author": "jijue",  # POC作者
        "version": "3",  # POC版本，默认是1
        "CreateDate": "2021-06-03",  # POC创建时间
        "UpdateDate": "2021-06-03",  # POC创建时间
        "PocDesc": """
            v2
            该POC支持中文，别的POC都不支持  
            该POC不支持burp代理，或许别的代理也不支持，笔者没测那么多，见谅  
            v3
            部分优化
            v4
            新增对Adobe ImageReady的支持
        """,  # POC描述，写更新描述，没有就不写

        "name": "url存活检测",  # 漏洞名称
        "VulnID": "",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "各类web应用",  # 漏洞应用名称
        "AppVersion": "",  # 受漏洞影响的应用版本
        "VulnDate": "2021-06-03",  # 漏洞公开的时间,不知道就写能查到的最早的文献日期，格式：xxxx-xx-xx
        "VulnDesc": """
        略
        """,  # 漏洞简要描述

        "fofa-dork": "略",  # fofa搜索语句
        "example": "",  # 存在漏洞的演示url，写一个就可以了
        "exp_img": "",  # 先不管

    }

    timeout = 20

    def _verify(self, retry_num=2):
        vuln = [False, ""]
        url = self.target  # url自己按需调整

        if url.startswith("http://") or url.startswith("https://"):
            headers = {"User-Agent": get_random_ua(), }

            try:
                proxy_handler = request.ProxyHandler(self.proxy)
                opener = request.build_opener(proxy_handler)
                request.install_opener(opener)

                # verify
                context = ssl._create_unverified_context()

                req = request.Request(url, headers=headers)
                response = request.urlopen(req, timeout=self.timeout, context=context)
                html = response.read()
                status_code = response.getcode()

                encode_mode = chardet.detect(html)["encoding"]

                try:
                    if encode_mode == None and len(
                            html) != 0:  # and b'\x89PNG' in html and b'Adobe ImageReady' in html:
                        html = html
                    elif encode_mode == None and len(html) == 0 and status_code == 200:
                        html = html
                    elif encode_mode.lower() == "gbk" or encode_mode.lower() == "gb2312" or encode_mode.lower() == "gb18030":
                        encode_mode = "gb18030"
                        html = html.decode(encode_mode)  # .encode("utf-8")
                except UnicodeDecodeError:
                    pass

                if str(status_code)[0] == "2" or \
                        str(status_code)[0] == "3" :
                    vuln = [True, html]

            except Exception as e:
                if retry_num > 0:
                    time.sleep(5)
                    self._verify(retry_num - 1)
            # except Exception as e:
            #     return [True, gen_title("!!! UnKnown Error: " + str(e))]
        else:
            vuln = [True, "No HTTP Protocal,Pass"]

        return vuln

    def _attack(self):
        return self._verify()
