# oFx


[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/)  [![License](https://img.shields.io/badge/license-GPLv3-brown.svg)](https://github.com/bigblackhat/oFx/blob/main/LICENSE)

## 简介
``中文名：三千雷``  

一个应用于web安全领域的漏洞扫描框架，可被应用于但不限于如下场景：
```
0Day/1Day全网概念验证(在没有懒得测试环境的情况下，直接写POC全网扫描，亲测很爽)

刷肉鸡(需要使用RCE/写文件等漏洞的POC)    

企业内网或对外开放资产的安全评估  

简单的拒绝服务攻击(用Url存活检测POC)
```

虽说是框架，但目前的规模仅是笔者自用及与身边小伙伴分享的工具  

#### Legal Disclaimer
```
Usage of oFx for attacking targets without prior mutual consent is illegal.
oFx is for security testing purposes only
```

#### 法律免责声明
```
未经事先双方同意，使用oFx攻击目标是非法的。
oFx仅用于安全测试与研究目的
```

![show](img/3.png)

黑底蓝字代表无漏洞  
![show](img/1.png)

黑底绿字代表存在漏洞  
![show](img/4.png)

黑底青字目标不可达  
![show](img/2.png)



网速尚可情况下，测试30个线程的速度：
![show](img/11.png)
Fofa会员一条搜索语句能提取一万条url，约11分钟跑完  


## 使用方法  


### 部署

```
git clone --depth 1 https://github.com/bigblackhat/oFx.git oFx
```

### 用前提醒
使用前提醒，oFx默认每次运行都会有报告和log的输出，分别在output和log文件夹下，出于缓解存储压力的考虑，笔者设定的规则为每次运行时都会删除12小时以前的输出文件，如果该输出文件对使用者有剩余价值，请在运行结束后及时将输出文件移出当前目录或更名为中/英文形式，如果有重要信息被删除，就再扫一遍吧，也快得很  

另外，oFx如今可以良好的运行于Mac和Kali系统，相信其他linux也可以正常运行，但由于笔者没有Windows测试环境，因此在Windows上运行oFx可能会发生一些不可预测的错误，请避免在Windows上运行oFx  

### 单个url扫描模式

单个url扫描模式的使用场景：
> POC功能性测试

使用方法  
```sh
➜  oFx git:(main) ✗ python3 ofx.py -s poc/Jboss/Jboss_Unauthorized_access/poc.py -u xxx.xxx.xxx.xxx:xx
```
> 单个目标的漏洞验证详情(返回取决于漏洞本身，目前所有POC都是为了批量验证而设计的，single检测模式尚没有对返回结果做优化，后续会有调整)  

![show](img/008.png)
漏洞存在与否见最后一行  

### 批量扫描模式

使用场景：  

> 新漏洞爆出来做全网验证  

> 刷CNVD之类的漏洞平台的积分或排名  

> 有RCE漏洞的POC的话，就可以刷肉鸡(见下方的[POC支持清单](#PocSupport))  

使用方法  
```sh
➜  oFx git:(main) ✗ python3 ofx.py -s poc/Jboss/Jboss_Unauthorized_access/poc.py -f scan/jboss001.txt --thread 30
```
也可以通过``,``分隔同时指定多个poc
```sh
➜  oFx git:(main) ✗ python3 ofx.py -s poc/Jboss/Jboss_Unauthorized_access/poc.py,poc/Jenkins/Unauth_Access/poc.py,poc/Alibaba_Druid/Unauth_Access/poc.py -f scan/jboss001.txt --thread 30
```
最后还可以通过``-s all``指定全量POC进行测试
```sh
➜  oFx git:(main) ✗ python3 ofx.py -s all -f scan/jboss001.txt --thread 50
```
全量POC下测试时常较久，建议食用方式：
* 根据自己电脑性能和带宽给到50个或更多的线程数  
* 睡前开始扫描或出门玩儿之前打开oFx进行全量POC测试  

### Fofa api 资产获取

通过fofa提供的api接口获取资产清单  

![show](img/009.png)

```sh
➜  oFx git:(main) ✗ python3 ofx.py --fofa-search

20xx-xx-xx xx:xx:xx,xxx - INFO: User : xxx@163.com | Key : xxx | 登陆成功
请输入结果保存文件名(不必加文件后缀)：jboss001
请输入搜索语句：app="Jboss"

20xx-xx-xx xx:xx:xx,xxx - INFO: Fofa搜索语句为：app="Jboss"，开始与Fofa Api对接
第1页获取成功
第2页获取成功
第3页获取成功
...
第99页获取成功
第100页获取成功

20xx-xx-xx xx:xx:xx,xxx - INFO: 搜索完毕，结果保存至/root/oFx/scan/jboss001.txt，经去重共计9748条
```

可以动态的修改user和key，无需打开配置文件调整，下次使用时直接生效不必重新输入user和key    

fofa search模式会将从api中获取到的结果进行去重并重新排序，因此虽然笔者设定逻辑为获取一万条url但大部分情况下都不会是正好一万条结果，请放心食用  

## POC支持清单<div id="PocSupport"></div>

<br>

oFx目前仅具备verify也就是漏洞识别的能力，并不负责漏洞的后续利用，以下漏洞目前已支持检测  

<br>


|应用|漏洞名称|POC路径|
|-|-|-|
|360|360天擎数据库未授权访问|``poc/360/TianQing_Unauth_Acceess/poc.py``|
|Alibaba_Druid|Druid未授权访问|``poc/Alibaba_Druid/Unauth_Access/poc.py``|
|Alibaba_Nacos|Nacos未授权访问|``poc/Alibaba_Nacos/Unauth_Access/poc.py``|
|Apache CouchDB|Apache Couchdb 远程权限提升 (CVE-2017-12635)|``poc/Apache_CouchDB/Priv_Escalation_CVE-2017-12635/poc.py``|
|Apache Flink|Apache Flink目录穿透 (CVE-2020-17519)|``poc/Apache_Flink/Dir_Traversal_CVE-2020-17519/poc.py``|
|碧海威 L7|碧海威 L7 弱口令漏洞|``poc/Bithighway_碧海威/Weak_Pass_L7/poc.py``|
|common(通用)|URL存活检测|``poc/common/Url_Alive/poc.py``|
||git信息泄露|``poc/common/Git_Info_Disclosure/poc.py``|
||svn信息泄露|``poc/common/Svn_Info_Disclosure/poc.py``|
|Coremail|Coremail 配置信息泄露漏洞|``poc/Coremail/Conf_Info_Disclosure/poc.py``|
|ElasticSearch|ElasticSearch 未授权访问|``poc/Elasticsearch/Unauth_Access/poc.py``|
||ElasticSearch 命令执行漏洞（CVE-2014-3120）|``poc/Elasticsearch/Cmd_Exec_MVEL_CVE-2014-3120/poc.py``|
||ElasticSearch Groovy 沙盒绕过 && 代码执行漏洞（CVE-2015-1427）|``poc/Elasticsearch/Code_Exec_Groovy_CVE-2015-1427/poc.py``|
||ElasticSearch 目录穿越漏洞（CVE-2015-5531）|``poc/Elasticsearch/Dir_Traversal_CVE-2015-5531/poc.py``|
||Elasticsearch写任意文件漏洞（WooYun-2015-110216）|``poc/Elasticsearch/File_Create_WooYun-2015-110216/poc.py``|
|Eyou 亿邮电子邮件系统|亿邮电子邮件系统 远程命令执行|``poc/Eyou_亿邮/RCE_moni_detail/poc.py``|
|F5|F5 BIG-IP任意文件读取(CVE-2020-5902)|``poc/F5_BIG_IP/File_Read_CVE_2020_5902/poc.py``|
|Jboss|Jboss未授权访问|``poc/Jboss/Unauth_Access/poc.py``|
|Jellyfin|Jellyfin任意文件读取|``poc/jellyfin/File_Read_CVE_2021_21402/poc.py``|
|Jenkins|Jenkins未授权访问|``poc/Jenkins/Unauth_Access/poc.py``|
|Kyan网络监控设备|Kyan网络监控设备信息泄露|``poc/Kyan/Info_Disclosure/poc.py``|
|蓝凌OA|蓝凌OA前台任意文件读取漏洞|``poc/Landray_蓝凌OA/File_Read_CNVD_2021_28277/poc.py``|
|迈普 ISG1000安全网关|迈普 ISG1000安全网关 任意文件下载漏洞|``poc/MaiPu_迈普/File_Download_webui/poc.py``|
|MessageSolution企业邮件归档管理系统|MessageSolution企业邮件归档管理系统 EEA 信息泄露|``poc/MessageSolution/Info_Disclosure/poc.py``|
|PHP|php v8.1开发版后门检测|``poc/php/Backdoor_v8dev/poc.py``|
|Redis|Redis未授权访问|``poc/Redis/Unauth_Access/poc.py``|
|Samsung|三星路由器本地文件包含|``poc/Samsung/Samsung_Wlan_AP_Lfi/poc.py``|
|SonarQube|SonarQube api 信息泄露漏洞|``poc/SonarQube/Info_Disclosure_CVE_2020_27986/poc.py``|
|电信天翼|电信天翼网关F460 web_shell_cmd.gch 远程命令执行漏洞|``poc/TianYi_天翼/RCE_F460_web_shell_cmd/poc.py``|
|泛微 OA|泛微 OA 8 前台SQL注入|``poc/Weaver_泛微OA/Sql_inj_E_cology_V8/poc.py``|
|用友NC|用友NC6.5 BeanShell RCE|``poc/Yonyou_用友NC/RCE_BeanShell_CNVD_2021_30167/poc.py``|
||用友ERP-NC 目录遍历漏洞|``poc/Yonyou_用友NC/Dir_List_ERP/poc.py``|

## 致谢清单

以下清单中的项目笔者都有参考或对笔者提供一定程度上的帮助，排名不分先后顺序，仅按照中文全拼首字母顺序排列  

|项目地址|
|-|
|[AngelSword](https://github.com/Lucifer1993/AngelSword)|
|[pocsuite3](https://github.com/knownsec/pocsuite3)|
|[sqlmap](https://github.com/sqlmapproject/sqlmap) yyds|
|[vulhub](https://vulhub.org/)|


<br>
<br>
<br>


## 错误提交

如果您在使用oFx的过程中遇到了一些笔者写代码时没有考虑到的问题或没有测试到的错误，欢迎通过邮箱告知笔者(ronginus@qq.com)  

邮件中需要包含触发错误的oFx命令，测试文件，您的运行环境（包括但不限于操作系统、python版本等），报错的字符串形式➕报错截图  


~~都看到这儿了，点个star再走呗~~

![show](img/10.jpg)

