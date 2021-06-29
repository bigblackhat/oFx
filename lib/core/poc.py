#coding : utf-8
from lib.core.common import url_handle
# from lib.core.log import logcritical
# import sys

class POCBase(object):

    def __init__(self,target,proxy = None):

        self.target = target

        if "://" in self.target and self.target.count(":") == 2:
            pass
        elif "://" not in self.target and self.target.count(":") == 1:
            self.target = url_handle(target)
        elif "://" in self.target and self.target.count(":") == 1:
            self.target = target+":80"
        elif self.target.count(":") == 0:
            self.target = "http://" + self.target + ":80"
        else:
            exit()

        self.protocol = self.target.split("://")[0]+"://"
        self.host = self.target.split("://")[1].split(":")[0]
        self.port = self.target.split("://")[1].split(":")[1]

        self.proxy = proxy
        self.timeout = 10


    def _honeypot_check(self,text):
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


        if "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" in text \
            and "var DEFAULT_PASSWD = \"admin\";" in text \
                and "HDS-7204TVI-HDMI/K 192.168.100.89,Digital Video Recorder" in text\
                    and "\"tagline\" : \"You Know, for Search\"" in text:
            return True

        return False

    def _verify(self):

        raise NotImplementedError

    def _attack(self):

        raise NotImplementedError

