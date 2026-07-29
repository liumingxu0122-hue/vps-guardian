# 端口流量运维

## 安装或升级

为目标架构构建 `./agent/nethelper`，并从可信发布清单取得 SHA-256。在隔离 Linux
节点执行：

```sh
sudo scripts/install-port-traffic-helper.sh \
  --binary /verified/path/vps-guardian-net-helper \
  --sha256 <64位小写十六进制>
```

安装器会校验产物和 systemd unit，创建 root-only 哈希回滚备份，安装 socket
激活 helper，任何失败均关闭。随后在现有 Agent 配置中设置：

```json
{"port_traffic_enabled":true,"net_helper_socket":"/run/vps-guardian-net-helper/helper.sock"}
```

只重启 Agent。通用 Agent 升级不得自动启用该功能。同一份 root-only 配置必须包含
Controller 签发的 `host_id`；helper 会把它与每个签名任务的目标核对，不匹配则拒绝。

首版只支持 systemd socket 激活。仓库当前没有既有 OpenRC Agent 生命周期，因此
不会宣称或生成未经验证的 OpenRC 特权 helper 服务；该项保留为独立的可移植性门禁。

## 策略流程

1. 在 Web 创建仅监控策略，验证真实 RX/TX 样本。
2. 至少观察一个完整重置周期，或执行一次已批准重置。
3. 为配额执行或出站限速创建高风险申请。
4. 由另一名 Admin/Owner 完成 Step-up、核对回滚并批准。
5. 验证任务结果、专属规则、计数连续性、告警和审计。

手工重置在申请和审批时都要求 `RESET <策略 UUID>`。创建策略时不能直接选择计划
重置，也不能直接编辑重置计划。计划重置属于独立的高风险变更：一名 Admin/Owner
提出申请，另一名 Admin/Owner 使用 `SCHEDULE <策略 UUID>` 批准。Controller
持久保存审批来源，只有来源完整时才会排队到期重置。计划按配置时区计算，事件和
存储时间仍为 UTC。

## 回滚与卸载

先通过审批关闭执行模式。升级失败时恢复安装器备份。卸载执行：

```sh
sudo scripts/uninstall-port-traffic-helper.sh
```

脚本先备份并哈希本地状态，再让 helper 移除 Guardian nftables/TC 对象，最后移除
socket unit 和二进制；默认保留本地状态。`--purge-local-state` 必须显式指定，
且不会删除 Controller 历史或审计。

## 数据保留

Controller 维护流程运行 `prune_port_traffic`：原始 7 天、小时 90 天、日 400 天。
重置事件和审计记录不参与该清理。
