

iptables-legacy 规则集的匹配记录，dmesg 是能看到的，但是iptables-nft 规则匹配记录dmesg 看不到，只能nft monitor trace。所以当用iptables 添加规则时，需要用iptables-legacy来查看是否有相应的规则，有就说明是iptables-legacy， 运行规则是需要加参数--backend iptables， 没有就说明是nft ，需要指定参数--backend nft

#### 记录数据包路径
```

Events:
#    kind      origin     table        chain              verdict   in         out        rule/raw
1    packet    temporary  nftracepath_2b51b437 trace_output       -         -          ens160     trace id b32cb952 inet nftracepath_2b51b437 trace_output packet: oif "ens160" ip saddr 192.16...
2    verdict   temporary  nftracepath_2b51b437 trace_output       -         -          -          trace id b32cb952 inet nftracepath_2b51b437 trace_output verdict continue
3    policy    temporary  nftracepath_2b51b437 trace_output       -         -          -          trace id b32cb952 inet nftracepath_2b51b437 trace_output policy accept
4    packet    -          raw          OUTPUT             -         -          ens160     trace id b32cb952 ip raw OUTPUT packet: oif "ens160" ip saddr 192.168.244.129 ip daddr 2.2.2....
5    verdict   system     raw          OUTPUT             -         -          -          trace id b32cb952 ip raw OUTPUT verdict continue
6    policy    policy     raw          OUTPUT             -         -          -          trace id b32cb952 ip raw OUTPUT policy accept
7    packet    -          mangle       OUTPUT             -         -          ens160     trace id b32cb952 ip mangle OUTPUT packet: oif "ens160" ip saddr 192.168.244.129 ip daddr 2.2...
8    rule      system     mangle       OUTPUT             accept    -          -          meta l4proto tcp ip daddr 2.2.2.2 tcp dport 88 counter packets 35 bytes 2100 accept (verdict ...
9    packet    -          filter       OUTPUT             -         -          ens160     trace id b32cb952 ip filter OUTPUT packet: oif "ens160" ip saddr 192.168.244.129 ip daddr 2.2...
10   verdict   system     filter       OUTPUT             -         -          -          trace id b32cb952 ip filter OUTPUT verdict continue
11   policy    policy     filter       OUTPUT             -         -          -          trace id b32cb952 ip filter OUTPUT policy accept
12   packet    -          mangle       POSTROUTING        -         -          ens160     trace id b32cb952 ip mangle POSTROUTING packet: oif "ens160" ip saddr 192.168.244.129 ip dadd...
13   verdict   system     mangle       POSTROUTING        -         -          -          trace id b32cb952 ip mangle POSTROUTING verdict continue
14   policy    policy     mangle       POSTROUTING        -         -          -          trace id b32cb952 ip mangle POSTROUTING policy accept
15   packet    temporary  nftracepath_2b51b437 final_postrouting  -         -          ens160     trace id b32cb952 inet nftracepath_2b51b437 final_postrouting packet: oif "ens160" ip saddr 1...
16   verdict   temporary  nftracepath_2b51b437 final_postrouting  -         -          -          trace id b32cb952 inet nftracepath_2b51b437 final_postrouting verdict continue
17   policy    temporary  nftracepath_2b51b437 final_postrouting  -         -          -          trace id b32cb952 inet nftracepath_2b51b437 final_postrouting policy accept
```

packet  = 包到达某个位置
rule    = 命中了某条规则
policy  = 没命中规则，走链默认策略
verdict = nft 给出的处理判定; 例如 accept、drop、continue、return、jump、goto 等。它更像是“执行结果事件”。
log     = nftracepath 自己加的探针日志



### 使用 $nftracepath-remote-verify 验证当前修改，远程机器是 root@192.168.4.24，端口 51000

### namespace 集成测试 和 host smoke 测试 分别是什么意思，测试的逻辑是什么
#### namespace 集成测试

这是仓库已有的 `scripts/remote_integration.sh`。它在远端机器上临时创建多个 network namespace 和 veth，把它们组成一个小型虚拟网络，用来测试 `nftracepath` 在“转发、本机接收、丢包、超时”这些路径里的行为。

逻辑大概是：

```text
client namespace
  10.88.1.2
      |
      veth
      |
router namespace
  10.88.1.1 / 10.88.2.1
      |
      veth
      |
server namespace
  10.88.2.2
```

测试项：

- `forward`：client 发包到 server，经过 router 转发，期望 outcome 是 `egress`
- `local`：client 发包到 server namespace 本机地址，期望 outcome 是 `local`
- `drop`：在 router namespace 里临时加 drop 规则，发包后期望 outcome 是 `drop`
- `timeout`：不发包，只监听，期望 outcome 是 `timeout`

它会分别尝试 `iptables` 和 `nft` 后端。但这台机器的内核不把 namespace 里的 iptables LOG/TRACE 暴露到可读 kernel log，所以 iptables 被跳过，nft 跑通了。

#### host smoke 测试

这是我们 skill 脚本额外生成的测试。它不是完全隔离在多个 namespace 里，而是在宿主机 namespace 上创建一个临时 bridge，再创建一个 namespace 模拟发包端，让数据包真正进入宿主机的 `INPUT` 路径。

逻辑大概是：

```text
netns nftp-host-xxx
  eth0 198.18.x.2:43101
      |
      veth
      |
bridge br-nftp-xxx 198.18.x.1:53101
      |
host namespace INPUT
```

测试逻辑：

1. 创建 bridge `br-nftp-xxx`。
2. 创建 veth pair。
3. 一端接到 bridge，另一端放进 netns。
4. 在宿主机 netfilter 上添加一条严格匹配的临时测试规则，例如：
   ```text
   udp 198.18.x.2:43101 -> 198.18.x.1:53101 accept
   ```
5. 从 netns 发送 UDP 包到 bridge 地址。
6. 运行 `nftracepath` 监听这个五元组。
7. 检查是否能看到 trace events，并确认命中了自动添加的测试规则。
8. 清理 bridge、veth、netns 和临时规则。

它的作用是补充验证宿主机 namespace 的真实 netfilter 行为，尤其是 namespace 集成测试里 iptables 被跳过时，host smoke 还能覆盖 `iptables-legacy`。这次失败就发生在这个补充测试里：iptables 规则确实命中了，但 outcome 没推成 `local`。