# custom-tcp-filter
Custom Tcp Header Options And When  Data Arrive  Netfilter Check It

### 1.项目由来
公司做物联网项目, 后台采用netty开发,端口暴露使之容易被扫描攻击。 故实现自定义TCP头, 这样可以在握手阶段就丢弃数据包.达到提高攻击门槛的目的。
此项目在一下系统中测试通过：

1. Ubuntu 14.04.1 LTS
2. CentOS Linux release 7.4.1708 (Core)

### 2.原理简介

根据TCP/IP协议, 在TCP协议头尾部定义了可选配置数据区; 此区域最大40字节; 故可利用此区域增加自定义的数据,然后在传输层进行解析识别; 达到身份验证的目的；
基于`linux` 的`netfilter`进行实现. hook `NF_IP_POST_ROUTING` 和 `NF_INET_PRE_ROUTING` 两个节点, 分别在数据流出时附带数据, 数据包流入时检查自定义头。


### 3.附录
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
