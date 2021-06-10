## version 1.0.0
----------------
初始版本


## version 2.0.0
----------------
改善v1存在的一些固有问题


## version 2.1.0
----------------
修复多线程时日志及报告生成存在缺陷的问题  

改善报告输出内容，新增网站Title内容  


## version 2.1.1  
-----------------  
添加初始化检测环境机制  


## version 2.1.2    
-----------------   
调整模块导入细节  
加入filescan模式计时功能  


## version 2.1.3    
-----------------   
添加url处理逻辑  
插件模版制作


## version 2.1.4
-----------------   
缓解因多线程带来的扫描末尾部分url不导入报告的问题    


## version 2.1.5  
-----------------   
插件模版优化  
新增url存活检测POC，并测试  

## version 2.2.0
-----------------   
添加tab级功能 - get target from fofa  


## version 2.2.1
-----------------   
之前缓解尾部url不导入报告问题仍存在一定的缺陷，通过添加poc timeout 时间校验，来进一步提高代码健壮性  


## version 2.2.2
-----------------   
单个url扫描模式调整，增加详细返回项  


## version 2.2.3
-----------------   
fofa功能用户交互场景下的一些体验调整  


## version 2.2.4
-----------------
修改readme，完善使用部分的详细描述  
完善参考致谢  


## version 2.2.5
-----------------
改善single-url检测模式下的url处理逻辑，提高代码的健壮性  


## version 2.2.8
-----------------
新增三个POC：  
Alibaba Druid未授权访问  
.git信息泄露  
Alibaba Nacos未授权访问  


## version 2.3.1
-----------------
添加随机user-agent功能   
优化POC模版  
新增一个POC：svn信息泄露  


## version 2.4.0 alpha 
-----------------
添加tab级功能 update


## version 2.3.3
-----------------
回退2.3.1  

添加一条POC：  
phpv8后门检测POC   

优化svn信息泄露POC  

优化help文字描述  

添加requirements.txt  


## version 2.3.5
-----------------
添加对python3的基本支持  
readme中新增当前已支持的POC列表  


## version 2.3.8
-----------------
出于存储考虑，添加日志与报告的自动clear功能  
整合version与author信息到info.ini中  
优化proxy的url处理   


## version 2.4.2
-----------------
修复因proxy调整带来的POC存在设计初考虑不周的问题  

添加两个POC:  
jenkins未授权访问  
jboss未授权访问    


## version 2.4.3
-----------------
设计更优雅的配色方案  


## version 2.4.4
-----------------
优化fofa搜索结果处理逻辑  
```
=======
-----以上为当前版本-----
=======
```


## version 2.4.7
-----------------
添加四个POC：  

ElasticSearch 未授权访问   
ElasticSearch 命令执行漏洞（CVE-2014-3120）  
ElasticSearch 代码执行漏洞（CVE-2015-1427）   
ElasticSearch 目录穿越漏洞（CVE-2015-5531）   

修改proxy的位置和调用逻辑，使之更优雅  

修改jellyfin文件读取POC的检测逻辑，降低误报率  

