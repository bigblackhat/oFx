#coding : utf-8
from lib.common import url_handle

class POCBase(object):

    def __init__(self,host,proxy = None):
        self.host = url_handle(host)
        self.proxy = proxy
        self.timeout = 10


    def _honeypot_check(self,text):
        _HoneyPot = False

        # F5 BIG-IP code
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
            _HoneyPot = True

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
            _HoneyPot = True

        return _HoneyPot

    def _verify(self):

        raise NotImplementedError

    def _attack(self):

        raise NotImplementedError

