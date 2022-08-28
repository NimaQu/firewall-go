# Firewall-go

## 使用 http 请求来操作 iptables 规则

GET  https://example.com:8000/$chain/filter/$action/$port?auth=$YOUR_API_KEY

e.g.: https://example.com:8000/input/filter/accept/15000?auth=114514

这将会在本机 iptables 添加一条允许 15000 端口通过 TCP 和 UDP 流量的规则，IP 为你发出请求的 IP

```bash
root@dev:~/firewall-go# iptables -nL
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     udp  --  1.2.3.4        0.0.0.0/0            udp dpt:15000
ACCEPT     tcp  --  1.2.3.4        0.0.0.0/0            tcp dpt:15000
DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpts:10000:20000
DROP       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpts:10000:20000
```

软件启动时会将你在 ENV 中配置的 IP 段自动应用 DROP 规则

因为 http 不安全，所以不支持 http 请求，请在 ENV 中配置 ssl 证书和 key