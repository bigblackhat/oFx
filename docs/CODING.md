# oFx - POC编写规范及要求说明

## 概述

本文档为oFx的PoC脚本编写规范及要求说明，包含了PoC脚本编写的步骤以及相关的一些说明。一个优秀的 PoC 离不开反复的调试、测试。  

目前oFx的POC编写为邀请制，仅笔者邀请者提交的POC贡献可被接受，其他有兴趣的小伙伴也可以提交代码贡献，笔者空闲时会抽时间阅读并测试，根据代码质量、漏洞危害程度等综合考量是否使用，POC通过者将会列入贡献感谢列表    

POC打包后，通过邮件发送至笔者的邮箱(ronginus@qq.com)，POC包内目录结构见下文[POC提交规范](#POCSubmitRule)

邮件标题为：``oFx_POC提交贡献：APP_NAME/VULN_NAME``

## POC编写规范<div id="PoCstandard"></div>

本工具专注于web安全领域，目前以围绕http协议的利用与检测方式为核心的漏洞作为POC编写最佳种类，涉及其他领域的漏洞，本工具概不接受   

### 自定义检测逻辑<div id="POCDiy"></div>
POC作者仅需专注于漏洞逻辑即可，修改_verify方法实现对漏洞的检测

漏洞存在与否直接修改vuln值，vuln为False即漏洞不存在，vuln为True即漏洞存在：  
```python
if req.status_code == 200 and "自己设计规则":
    vuln = [True,req.text]
else:
    vuln = [False,req.text]
```
杜绝垃圾规则，人人有责，包括但不限于如下用例的检测规则都属于垃圾规则：
```py
if req.status_code == 200 and "" in req.text:
```
```py
if req.status_code == 200 and "Administrator" in req.text:
```
```py
if req.status_code != 500:
```
```py
if req.status_code == 200 and "fonts" and "extensions" and "mci extensions"in  req.text :
```
在FoFa、Shodan等工具的帮助下，我们能够搜索到大量适合某某POC测试的目标，因此上面的逻辑很可能在专项测试的时候可以良好的运行，但如果是一个测试文件中包含了大量的完全不受控制的未知的目标(别不信，互联网上什么样的网站都有)，那么上面的检测逻辑将会产生大量的误报，俗称白给。  

言而总之，检测逻辑越苛刻越好  

### POC_info信息<div id="POCinfoWrite"></div>
每一个POC都必须写好_info属性的值，具体细节见注释处内容  
```python
_info = {
    "author" : "jijue",                      # POC作者
    "version" : "1",                    # POC版本，默认是1  
    "CreateDate" : "2021-06-09",        # POC创建时间
    "UpdateDate" : "2021-06-09",        # POC创建时间
    "PocDesc" : """
    略  
    """,                                # POC描述，写更新描述，没有就不写

    "name" : "Demo",                        # 漏洞名称
    "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
    "AppName" : "",                     # 漏洞应用名称
    "AppVersion" : "",                  # 漏洞应用版本
    "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
    "VulnDesc" : """
    
    """,                                # 漏洞简要描述

    "fofa-dork":"",                     # fofa搜索语句
    "example" : "",                     # 存在漏洞的演示url，写一个就可以了
    "exp_img" : "",                      # 先不管  
}
```

### verify检测逻辑预定义

针对不同的漏洞有不同的利用形式，返回信息也可以截然不同，因此这里做一个规范，针对什么漏洞应该如何利用，当匹配成功就算是漏洞存在？

|漏洞类型|检测手段|
|-|-|
|弱口令|登陆，根据登陆成功/失败的返回信息做判断，存在弱口令则将其返回给``vuln[2]``|
|文件下载/读取|默认读``/etc/passwd``，windows系统则读取``/C:/Windows/win.ini``|
|命令/代码执行|执行``cat /etc/passwd``命令，取root那一行中的部分字符``root:/root``作为识别依据即可|
|未授权访问|略|
|用户创建|新建账户/口令返回给``vuln[2]``|
|||


<!-- 
### attack攻击模式逻辑预定义
``attack模式输入future范畴，下面表格仅是笔者的畅想``

|漏洞类型|攻击逻辑|
|-|-|
|弱口令|不需要攻击模式|
|代码/命令执行|获取用户输入的命令并发送给目标执行|
||一键反弹shell|
|文件读取/下载|获取用户输入的路径并返回内容|
||一键读取系统核心文件|
|写文件/文件上传|一键挂马|
 -->
## POC规范说明<div id="POCRule"></div>


### POC第三方依赖说明<div id="requires"></div>

写POC尽量不要使用第三方模块，如果一定要用，请在``_info``的``PocDesc``中注明    

如果经笔者考量该POC不适合oFx，则该POC将会被废弃  

### POC命名规范<div id="POCNameRule"></div>

POC统一放在``poc/``目录下，以``应用名/漏洞名/poc.py``的三段式格式来给oFx统一调度  

漏洞名部分格式为：``漏洞类型`` + ``_(下划线)`` + ``漏洞编号``

漏洞类型写简称，具体见下文[漏洞类型命名规范](#VulnNameRule)

漏洞编号以CVE为主，没有CVE就CNVD或CNNVD或WOOYUN，实在没有且不影响分辨的话，可以不写编号  

举个栗子：
```
Druid未授权访问

如下：

poc/Alibaba_Druid/UnAuth_Access/poc.py
```

如果同一个应用存在两个及以上相同类型的漏洞，可以根据存在漏洞的文件或利用链等区分，格式为：``漏洞类型`` + ``_(下划线)`` + ``漏洞文件`` + ``_(下划线)`` + ``漏洞编号``  


### 漏洞类型命名规范<div id="VulnNameRule"></div>

以下表格尚不完善，如果POC作者有新的漏洞种类需求，可先自行起名，然后提交POC给笔者，笔者会酌情修改或接受录入下表

|漏洞名|英文名|缩写|
|-|-|-|
|Sql注入|SQL Injection|Sql_inj|
|XML注入|XMl Injection|XML_inj|
|命令注入|Command Injection|Cmd_inj|
|模板注入|Server-Side Template Injection|Ssti|
|未授权访问|Unauthorized Access|UnAuth_Access|
|权限提升|Privilege escalation|Priv_Escalation|
|命令执行|Command Execution|Cmd_Exec|
|代码执行|Code Execution|Code_Exec|
|远程文件包含|Remote File Inclusion|Rfi|
|本地文件包含|Local File Inclusion|Lfi|
|任意文件创建|Arbitrary File Creation|File_Create|
|任意文件读取|Arbitrary File Read|File_Read|
|任意文件下载|Arbitrary File Download|File_Download|
|任意文件删除|Arbitrary File Deletion|File_Delete|
|目录遍历|Directory Listing|Dir_List|
|目录穿越|Directory Traversal|Dir_Traversal|
|文件上传|File Upload|File_Upload|
|弱密码|Weak Password|Weak_Pass|
|信息泄露|Information Disclosure|Info_Disclosure|
|配置信息泄露|Config Information Disclosure|Conf_Info_Disclosure|
|后门|Backdoor|Backdoor|
||||

### POC提交规范<div id="POCSubmitRule"></div>

考虑到需要测试用例与success用例，oFx并不接受Github提交贡献，POC提交打zip包通过邮件发给笔者，以下表格中的内容为提交POC时的格式规范，缺一不收  

|文件|要求|
|-|-|
|POC本身|注意目录结构!|
|测试用例txt文件|fofa搜索结果不少于一万条的，用例中数据至少一万条，不足一万条的，有多少给多少|
|测试成功案例txt文件|大于等于30条的，至少给到30条，不足30条的，有多少给多少|
|reference目录|包含漏洞介绍、利用等相关技术文章的url以及关于利用或检测该漏洞的简要文字描述(``写入reference.md``)或pdf文件(``作为other file存入reference文件夹``)|

目录结构大致如下：
```
__________POC提交文件夹必须包含以下文件__________
|__ APP_NAME/
    |__ VULN_NAME/
        |__ poc.py
        |__ reference/
            |__ reference.md
            |__ other file
            |__ test_num_1w.txt
            |__ success_30.txt
```


考虑到每写一个POC都要手动的创建如上目录有点麻烦，因此笔者提供了一个POC目录结构生成器，食用方式如下：
```sh
➜  oFx git:(main) ✗ python3 ofx.py --gen-poc

        _  ______
    ___ |  ___|_  __
    / _ \| |_  \ \/ /
    | (_) |  _|  >  <__ _Author : jijue
    \___/|_| __/_/\_\__ __ __Version : 2.9.1

    #*#*#  https://github.com/bigblackhat/oFx  #*#*#

       _-___________________________________-_


请输入受漏洞影响的应用名Apache_Example
请输入漏洞名RCE

___________生成POC目录结构如下____________
    |__ Apache_Example/
        |__ RCE/
            |__ poc.py
            |__ reference/
                |__ reference.md
                |__ other file
                |__ test_num_1w.txt
                |__ success_30.txt
_________________________________________
POC路径为/Users/jijue/Documents/GitHub/oFx/poc/Apache_Example/RCE/
```


### POC测试流程

1.单个目标测试，直到检测逻辑正确，具备漏洞检测能力为止，并确保漏报在百分之十以下
2.fofa搜索结果，批量测试，降低误报
3.用``data/__The__One__File__.txt``测试，进一步降低误报