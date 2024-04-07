# ShadowResolve 说明

测试需要，满足伪造源IP，模拟众多客户端进行访问测试。同时也支持edns携带dns的源地址进行查询

**注意 ShadowResolve的开发是为了测试使用，请不要拿来干坏事**
**ShadowResolve具有伪造源地址的能力，可能会被杀毒关注**
**release提供的二进制文件为Github自动编译的结果，若不放心可以自行下载python源码使用**

使用本工具需要提供以下内容：
1. 域名列表：需要包含域名，请求类型
2. 客户IP列表：想要模拟的IP列表，计划支持地址范围、掩码、单独IP

此外，还对网络有些要求：
1. 添加回执路由：路由器需要将源地址为dnsIP的所有回包都转发给发包机，否则ShadowResolve无法完成收包。
2. 关闭系统防火墙：ShadowResolve不是使用的正常发包方法，防火墙可能会干扰收包。
3. 没有路由器的情况下，你可以在目前设备上配置静态路由到发包机，并取消路由网关的配置（这个会导致数据包不听主路由表的）
4. 建议在路由器上完成路由下一跳的指定，这样不用关闭ZDNS上面的路由网关。

## 域名列表格式

```text
www.baidu.com A
www.jd.com A
```

## IP列表的格式

```text
192.168.1.1/32
10.0.0.0/24 # 掩码会被展开成IP，/24等于256个IP。
```