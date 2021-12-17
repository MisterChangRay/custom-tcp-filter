# custom-tcp-filter
通过linux netfilter 扩展得 TCP自定义封包过滤器。
Custom Tcp Header Options And When  Data Arrive  Netfilter Check It

[![GitHub (pre-)release](https://img.shields.io/github/release/misterchangray/custom-tcp-filter/all.svg)](https://github.com/misterchangray/custom-tcp-filter) 
[![GitHub issues](https://img.shields.io/github/issues/misterchangray/custom-tcp-filter.svg)](https://github.com/misterchangray/custom-tcp-filter/issues) 
[![GitHub closed issues](https://img.shields.io/github/issues-closed/misterchangray/custom-tcp-filter.svg)](https://github.com/misterchangray/custom-tcp-filter/issues?q=is%3Aissue+is%3Aclosed) 
[![GitHub](https://img.shields.io/github/license/misterchangray/custom-tcp-filter.svg)](./LICENSE)

### 1.项目由来
公司做物联网项目, 后台采用netty开发,端口暴露使之容易被扫描攻击。 故实现自定义TCP头, 这样可以在握手阶段就丢弃数据包.达到提高攻击门槛的目的。
此项目在一下系统中测试通过：

1. Ubuntu 9.3.0-10ubuntu2 (2021年测试)
	- 内核版本 Linux version 5.4.0-42-generic
	- iptables v1.8.4 (legacy)
	- gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)
3. CentOS Linux release 8.2.2004 (Core) (2021年测试)
	- 内核版本4.18.0-193.el8.x86_64
	- iptables v1.8.4 (nf_tables)
	- gcc version 8.3.1 20191121 (Red Hat 8.3.1-5) (GCC)


### 2.原理简介

根据TCP/IP协议, 在TCP协议头尾部定义了可选配置数据区; 此区域最大40字节; 故可利用此区域增加自定义的数据,然后在传输层进行解析识别; 达到身份验证的目的；
基于`linux` 的`netfilter`进行实现. hook `NF_IP_POST_ROUTING` 和 `NF_INET_PRE_ROUTING` 两个节点, 分别在数据流出时附带数据, 数据包流入时检查自定义头。

### 3.快速开发
 - 搭建linux内核开发环境
 - 下载源码进入目录
 - 执行`./rebuild.sh`

### 4.附录
1. 资料参考
	1. [TCP/IP协议头部结构体](https://www.cnblogs.com/RodYang/p/3322250.html)
	2. [linux netfilter 五个钩子点](https://www.cnblogs.com/codestack/p/10850642.html)
	3. [使用netfilter实现输出报文的tcp option增加](https://blog.csdn.net/idleperson/article/details/52024864?utm_source=blogxgwz0)
	4. [一种验证tcp连接安全性的方法](https://patents.google.com/patent/CN103532964B/zh)
	5. [Linux内核网络数据包处理流程](https://www.cnblogs.com/muahao/p/10861771.html)

2. 思维扩展
	1. 可以利用自定义算法在传输层进行数据加解密
	2. 利用自定义字节在握手阶段断开链接
	3. 内网的网络安全

### 5. 其他
	- 下载`custom_tcp_filter.ko`文件
	- 使用 `sudo insmod custom_tcp_filter.ko` 命令进行安装
		-  `sudo insmod custom_tcp_filter.ko port=3306` 只对3306端口进行流入过滤,流出封装
		-  `sudo insmod custom_tcp_filter.ko port=3306,3309` 对3306-3309端口进行流入过滤,流出封装, 支持端口区间
		-  `sudo insmod custom_tcp_filter.ko inPort=3306,3308` 对3306,3308端口流入数据包进行过滤,不支持端口区间
		-  `sudo insmod custom_tcp_filter.ko outPort=3306,3323` 对3306,3323端口流出数据包进行封装,不支持端口区间
	- 使用 `sudo rmmod custom_tcp_filter` 命令进行卸载
	- 安装完成后通过dmesg 查看启动日志, 如发现`Custom tcp filter init successed`类似日志即启动成功
	- 内核应用可能导致系统蓝屏, 请注意系统版或修改后在使用。建议优先在测试环境测试完成后再应用到线上。

V1.0.1
- 升级hook方式
- 新增配置,可指定端口
- 可以配置流入流出端口
