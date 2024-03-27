# ssp
## 简介

​	在日常渗透工作中，遇到很多Spring框架搭建的服务，很多都是Whitelabel Error Page页面，对于Spring的扫描工具github中也有很多项目 python的 java的，但使用go的就很少。因为自身电脑的缘故 使用go编译的工具 加入环境变量中 能让我很方便的使用命令行来使用这些命令行工具，做到打开命令行就能进行 "随手一测"。而像python，java写的类似图形化的工具，我需要进入到相关目录中运行或者双击才能进行使用，对于我这种非常不喜欢找文件的人来说，使用go编译的可执行文件加入环境变量中使用，对我来说是极大的方便。加上最近在学习go语言就想着写一个玩玩，顺便练习一下自己的代码能力。

ssp是一个一个用于探测和利用Spring框架中常见漏洞的工具，使用Go语言开发。

本项目的POC来自开源项目[AabyssZG](https://github.com/AabyssZG)/[SpringBoot-Scan](https://github.com/AabyssZG/SpringBoot-Scan)和互联网收集。	

本项目信息泄露端点取自https://blog.zgsec.cn/archives/129.html

该工具支持探测和利用多个Spring框架版本的漏洞，包括：

- 2023 JeeSpringCloud任意文件上传漏洞
- CVE-2022-22947 Spring Cloud Gateway SpELRCE漏洞
- CVE-2022-22963 Spring Cloud Function SpEL RCE漏洞
- CVE-2022-22965 Spring Core RCE漏洞
- CVE-2021-21234 任意文件读取漏洞
- 2021 SnakeYAML_RCE漏洞
- 2021 Eureka_Xstream反序列化漏洞
- 2020 Jolokia配置不当导致RCE漏洞
- CVE-2018-1273 Spring Data Commons RCE漏洞

## 功能特性

- 支持单个URL的Spring信息泄露探测，包括暴露Spring框架版本、配置文件路径等。
- 支持对文件中包含的多个URL进行Spring信息泄露探测，方便批量扫描。
- 支持单个URL的Spring漏洞探测。
- 支持对文件中包含的多个URL进行Spring漏洞批量探测，提高效率。

## 使用方法

#### 对单个目标进行端点探测

```
ssp -u http://example.com
```

![image-20240308002601931](https://s2.loli.net/2024/03/08/3QIuYTsypHgCfVx.png)



#### 批量目标敏感端点

```
ssp -uf filename.txt
```

![image-20240308003301537](https://s2.loli.net/2024/03/08/nWTglbwGhiY2573.png)



#### 对单个目标进行漏洞探测

如若探测出漏洞 会进入漏洞利用模块

```
ssp -v http://example.com
```

![image-20240308003429226](https://s2.loli.net/2024/03/08/9mnivTDrEGV4Kg2.png)

如若探测出漏洞 会进入漏洞利用模块 进行漏洞利用

![image-20240308003552055](https://s2.loli.net/2024/03/08/74XfetmM8TZYryN.png)

输入响应的漏洞编号 进行漏洞利用 执行shell等

![image-20240308003722543](https://s2.loli.net/2024/03/08/dEnwy2UvI8BbtKj.png)



#### 批量目标漏洞探测

```
ssp -vf filename.txt
```

![image-20240308004237336](https://s2.loli.net/2024/03/08/f34I6xF8VanHikN.png)

## 注意事项

- 使用本工具进行探测和利用漏洞时，请务必遵守相关法律法规，仅在授权的范围内使用。
- 对未经授权的系统进行漏洞扫描和利用可能触犯法律，造成法律责任。
- 使用本工具时请注意网络环境安全，避免对生产系统造成影响。

## 免责声明

本工具仅用于技术研究和教育目的，请勿用于非法活动，使用者造成的任何后果与作者无关。

## 最后

如果您方便的话，辛苦您为作者主页的个人项目点个star~ 并关注一下公众号：**SSP安全研究**

有什么问题 或者 要加的功能 请提交工单给我~ 

![扫码_搜索联合传播样式-白色版](https://github.com/sspsec/ssp/assets/142762749/0654010c-cdcc-4cf5-8f22-fc33b8d86642)

