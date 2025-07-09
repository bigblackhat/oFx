# coding : utf-8
from lib.core.common import url_handle
from lib.core.log import logvuln, logwarning


# import re

class POCBase(object):

    def __init__(self, target, proxy=None):

        self.target = target[:-1] if target.endswith("/") else target

        if "://" in self.target and self.target.count(":") == 2:
            pass
        elif "://" not in self.target and self.target.count(":") == 1:
            self.target = url_handle(target)

        elif "://" in self.target and self.target.count(":") == 1:
            # self.target = target+":80"
            pass
        elif self.target.count(":") == 0:
            self.target = "http://" + self.target + ":80"
        else:
            err_msg = "url不符合规则，请输入类似于：http://ip:port 的target"
            exit()

        self.protocol = self.target.split("://")[0] + "://"
        self.host = self.target.split("://")[1].split(":")[0]
        if self.target.count(":") == 2:
            self.port = self.target.split("://")[1].split(":")[1]
        else:
            self.port = None

        if proxy == None:
            self.proxy = None
        elif proxy == "proxypool":
            proxy = self.get_proxy_from_api()
            self.setproxy(proxy)
        else:
            self.proxy = {"http": proxy}  # socks代理：socks://xx.x.x.x:xxx, http代理：http://xx.x.x.x:xx
        self.timeout = 45

    def get_proxy_from_api(self):
        import requests, json
        while True:
            try:
                req = requests.get("http://127.0.0.1:5010/get")
            except Exception as e:
                logwarning(f"代理获取失败，原因：{e}")
                return None
            obj = json.loads(req.text)
            proxyurl = obj["proxy"]

            if "中国" not in obj['region']:
                req = requests.get(f"http://127.0.0.1:5010/delete?proxy={proxyurl}")
                logwarning(
                    f"代理获取：{proxyurl}，地理位置：{obj['region']}，来源：{obj['source']}，该代理为境外代理，已抛弃，正在重新获取国内代理")
                continue

            req = requests.get("http://httpbin.org/get", proxies={"http": "http://" + proxyurl}, timeout=20)
            if req.status_code != 200:
                req = requests.get(f"http://127.0.0.1:5010/delete?proxy={proxyurl}")
                logwarning(
                    f"代理获取：{proxyurl}，地理位置：{obj['region']}，来源：{obj['source']}，该代理经测试疑似不可用，已抛弃，正在重新获取国内代理")
                continue
            break
        logvuln(f"代理获取成功：{proxyurl}，地理位置：{obj['region']}，来源：{obj['source']}")
        return proxyurl

    def setproxy(self, proxy):
        """
        set the proxy for oFx running

        return:None
        """
        if proxy == None:
            self.proxy = None
            return

        if proxy.startswith("http://"):
            proxy = proxy[7:]
        elif proxy.startswith("https://"):
            proxy = proxy[8:]
        else:
            pass

        if proxy.endswith("/"):
            proxy = proxy[:-1]
        else:
            pass

        self.proxy = {
            "http": "http://%s" % (proxy),
            "https": "http://%s" % (proxy),
        }

    def _honeypot_check(self, text):
        text = str(text)

        honeycode = """
     <title>NETZEN</title>
     <title>NOVIcam WEB</title>
     <title>Object moved</title>
     <title>onyphe.io</title>
     <title>OoklaServer</title>
     <title>Openfire Admin Console</title>
     <title>Openfire Console d'Administration: Configuration du Serveur</title>
     <title>Openfire Setup</title>
     <title>Password required</title>
     <title>phpinfo()</title>
     <title>phpMyAdmin</title>
     <title>phpMyAdmin </title>
     <title>PlayerasTangamanga.app</title>
     <title>Proxy Scanning in progress</title>
     <title>QNAP</title>
     <title>Recording Management System</title>
     <title>Residential Gateway Login</title>
     <title>RouterOS router configuration page</title>
     <title>SPORTING NEWS &#8211; News from sports world &#8211; now updated daily!</title>
     <title>The Best Online Casinos for USA Players</title>
     <title>torservers.net - Anonymizer Tor Exit Router</title>
"""
        if honeycode in text:
            return True

        ########## 可可爱爱的分割线 ############

        honeycode = """
WWW-Authenticate: Basic realm="AXIS_00408CD0EC74"
WWW-Authenticate: Basic realm="NETGEAR DGN2200"
WWW-Authenticate: Basic realm="NETGEAR D6300B"
WWW-Authenticate: Basic realm="NETGEAR DGN1000B"
Www-Authenticate: Basic realm="SickBeard"
WWW-Authenticate: Basic realm="netcam"
WWW-Authenticate: Basic realm="NETGEAR R7000"
WWW-Authenticate: Basic realm="NETGEAR R6400"
WWW-Authenticate: Basic realm="Broadcom Home Gateway Reference Design"
WWW-Authenticate: Basic realm="hikvision"
WWW-Authenticate: Basic realm="NETGEAR WGR614v10"
WWW-Authenticate: Basic realm="NETGEAR Orbi-mini"
WWW-Authenticate: Basic realm="NETGEAR Orbi"
WWW-Authenticate: Basic realm="Linksys-CIT400"
WWW-Authenticate: Basic realm="Login to the Router Web Configurator"
WWW-Authenticate: Basic realm="NETGEAR Orbi-micro"
WWW-Authenticate: Digest realm="IPCamera Login"
WWW-Authenticate: Basic realm="TP-LINK Wireless Dual Band Gigabit Router WDR4300"
"""

        if honeycode in text:
            return True

        ########## 可可爱爱的分割线 ############

        honeycode = """
windows--2017
write = system,call,log,verbose,command,agent,user,originate
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
},
荣耀立方
-->
</p>
</body></html>
"""

        if honeycode in text:
            return True

        ########## 可可爱爱的分割线 ############

        if "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" in text \
                and "var DEFAULT_PASSWD = \"admin\";" in text \
                and "HDS-7204TVI-HDMI/K 192.168.100.89,Digital Video Recorder" in text \
                and "\"tagline\" : \"You Know, for Search\"" in text:
            return True

        ########## 可可爱爱的分割线 ############

        honeycode = """
var TAB_CODE=9
var DEL_CODE=46
var BS_CODE=8
var SP_CODE=32
var DOT_CODE=190
var DOT2_CODE=110

var IDX_ON=0
var IDX_OFF=1

var IDX_AP_MODE=0
var IDX_CBRIDGE_MODE=1
var IDX_WWAN_MODE=2
var IDX_KAI_MODE=3
var IDX_MBRIDGE_MODE=4
"""
        if honeycode in text:
            return True

        return False

    def _verify(self):

        raise NotImplementedError

    def _attack(self):

        raise NotImplementedError
