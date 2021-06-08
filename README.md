# oFx
[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/)

## 简介
一个应用于web安全领域的漏洞扫描框架，刷洞，刷肉鸡用（取决于你的漏洞）  

虽说是框架，但目前的规模仅是笔者自用及与身边小伙伴分享的工具  

#### Legal Disclaimer

Usage of oFx for attacking targets without prior mutual consent is illegal.
oFx is for security testing purposes only

#### 法律免责声明
未经事先双方同意，使用oFx攻击目标是非法的。
oFx仅用于安全测试目的

![show](img/3.png)

黑底蓝字代表无漏洞  
![show](img/1.png)

黑底绿字代表存在漏洞  
![show](img/4.png)

黑底青字目标不可达  
![show](img/2.png)

网速尚可情况下，测试10个线程的速度：
![show](img/5.png)
也就是4分钟1000条  

网速尚可情况下，测试20个线程的速度：
![show](img/6.png)
两分钟跑完1000条  

网速尚可情况下，测试25个线程的速度：
![show](img/7.png)
约22分钟跑完一万条  


## 使用方法  


### 部署

```
git clone --depth 1 https://github.com/bigblackhat/oFx.git oFx
```
使用前提醒，oFx默认每次运行都会有报告和log的输出，分别在output和log文件夹下，出于缓解存储压力的考虑，笔者设定的规则为每次运行时都会删除12小时以前的输出文件，如果该输出文件对使用者有剩余价值，请在运行结束后及时将输出文件移出当前目录或更名为中/英文形式，如果有重要信息被删除，就再扫一遍吧，也快得很  

### 单个url扫描模式

单个url扫描模式的使用场景：
> POC功能性测试

> 单个目标的漏洞验证详情(取决于POC)  

![show](img/8.png)

### 批量扫描模式

使用场景：  

> 新漏洞爆出来做全网验证  

> 刷CNVD之类的漏洞平台的积分或排名  

> 有RCE漏洞的POC的话，就可以刷肉鸡  

### fofa api 资产获取

通过fofa提供的api接口获取资产清单  

![show](img/9.png)

可以动态的修改user和key，无需打开配置文件调整，下次使用时直接生效不必重新输入user和key    


## POC支持清单
|应用|漏洞名称|POC路径|
|-|-|-|
|通用|URL存活检测|``poc/common/url_alive/poc.py``|
|git|git信息泄露|``poc/common/git_info_leakage/poc.py``|
|svn|svn信息泄露|``poc/common/svn_info_leakage/poc.py``|
|Alibaba_Druid|Druid未授权访问|``poc/Alibaba_Druid/druid_access/poc.py``|
|Alibaba_Nacos|Nacos未授权访问|``poc/Alibaba_Nacos/Alibaba_Nacos_access/poc.py``|
|Jellyfin|Jellyfin任意文件读取|``poc/jellyfin/jellyfin_fileread_scan/poc.py``|
|Jenkins|Jenkins未授权访问|``poc/Jenkins/Jenkins_Unauthorized_access/poc.py``|
|Jboss|Jboss未授权访问|``poc/Jenkins/Jenkins_Unauthorized_access/poc.py``|
|PHP|php v8.1开发版后门检测|``poc/php/php_v8dev_backdoor/poc.py``|

## 致谢清单

以下清单中的项目笔者都有参考，排名不分先后顺序，仅按照中文全拼首字母顺序排列  

|项目地址|
|-|
|[pocsuite3]()|
|[sqlmap]()|


