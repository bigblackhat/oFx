# oFx


[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/)


## 简介
``中文名：三千雷``  

一个应用于web安全领域的漏洞扫描框架，刷洞，刷肉鸡用（取决于你的漏洞）  

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
约11分钟跑完一万条  


## 使用方法  


### 部署

```
git clone --depth 1 https://github.com/bigblackhat/oFx.git oFx
```

### 用前提醒
使用前提醒，oFx默认每次运行都会有报告和log的输出，分别在output和log文件夹下，出于缓解存储压力的考虑，笔者设定的规则为每次运行时都会删除12小时以前的输出文件，如果该输出文件对使用者有剩余价值，请在运行结束后及时将输出文件移出当前目录或更名为中/英文形式，如果有重要信息被删除，就再扫一遍吧，也快得很  


### 单个url扫描模式

单个url扫描模式的使用场景：
> POC功能性测试

使用方法  
```sh
➜  oFx git:(main) ✗ python3 ofx.py -s poc/Jboss/Jboss_Unauthorized_access/poc.py -u xxx.xxx.xxx.xxx:xx
```
> 单个目标的漏洞验证详情(取决于POC)  

![show](img/008.png)

### 批量扫描模式

使用场景：  

> 新漏洞爆出来做全网验证  

> 刷CNVD之类的漏洞平台的积分或排名  

> 有RCE漏洞的POC的话，就可以刷肉鸡  

使用方法  
```sh
➜  oFx git:(main) ✗ python3 ofx.py -s poc/Jboss/Jboss_Unauthorized_access/poc.py -f scan/jboss001.txt --thread 30
```

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

fofa search模式会将从api中获取到的结果进行去重并重新排序，因此大部分情况下都不会是正好10000条结果，往往只有6-7k也是合情合理的，请放心食用  

## POC支持清单

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
|common(通用)|URL存活检测|``poc/common/Url_Alive/poc.py``|
||git信息泄露|``poc/common/Git_Info_Disclosure/poc.py``|
||svn信息泄露|``poc/common/Svn_Info_Disclosure/poc.py``|
|ElasticSearch|ElasticSearch 未授权访问|``poc/Elasticsearch/Unauth_Access/poc.py``|
||ElasticSearch 命令执行漏洞（CVE-2014-3120）|``poc/Elasticsearch/Cmd_Exec_MVEL_CVE-2014-3120/poc.py``|
||ElasticSearch Groovy 沙盒绕过 && 代码执行漏洞（CVE-2015-1427）|``poc/Elasticsearch/Code_Exec_Groovy_CVE-2015-1427/poc.py``|
||ElasticSearch 目录穿越漏洞（CVE-2015-5531）|``poc/Elasticsearch/Dir_Traversal_CVE-2015-5531/poc.py``|
||Elasticsearch写任意文件漏洞（WooYun-2015-110216）|``poc/Elasticsearch/File_Create_WooYun-2015-110216/poc.py``|
|F5|F5 BIG-IP任意文件读取(CVE-2020-5902)|``poc/F5_BIG_IP/File_Read_CVE_2020_5902/poc.py``|
|Jboss|Jboss未授权访问|``poc/Jboss/Unauth_Access/poc.py``|
|Jellyfin|Jellyfin任意文件读取|``poc/jellyfin/File_Read_CVE_2021_21402/poc.py``|
|Jenkins|Jenkins未授权访问|``poc/Jenkins/Unauth_Access/poc.py``|
|Kyan网络监控设备|Kyan网络监控设备信息泄露|``poc/Kyan/Info_Disclosure/poc.py``|
|MessageSolution企业邮件归档管理系统|MessageSolution企业邮件归档管理系统 EEA 信息泄露|``poc/MessageSolution/Info_Disclosure/poc.py``|
|PHP|php v8.1开发版后门检测|``poc/php/Backdoor_v8dev/poc.py``|
|Redis|Redis未授权访问|``poc/Redis/Unauth_Access/poc.py``|

## 致谢清单

以下清单中的项目笔者都有参考或对笔者提供一定程度上的帮助，排名不分先后顺序，仅按照中文全拼首字母顺序排列  

|项目地址|
|-|
|[AngelSword](https://github.com/Lucifer1993/AngelSword)|
|[pocsuite3]()|
|[sqlmap]()|
|[vulhub](https://vulhub.org/)|


<br>
<br>
<br>

~~都看到这儿了，点个star再走呗~~

![show](img/10.jpg)