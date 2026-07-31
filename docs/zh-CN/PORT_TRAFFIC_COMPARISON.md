# 端口流量设计对比

## 已审查来源

- `duya07/port-traffic-dog` 固定提交
  `c8c91c527fc4beb11e48e9c6fde4627f75fc2dd2`；
- 其文档指向的上游 `zywe03/realm-xwPF` 固定提交
  `e5dc720fb64b41bfd449cc84fc0c17d7b09b910d`，包含 MIT License
 （Copyright 2025 zywe）。

定制仓库没有 LICENSE 文件。因此 Guardian 只把它作为设计参考，并追溯到明确授权
的上游。此次没有复制大型函数、脚本主体、通知实现、安装器或配置导出；Guardian
代码是独立的 Apache-2.0 实现。

## 诚实对比

`port-traffic-dog` 在单机运维上有明显优势：一个 Shell 工作流覆盖 nftables
计数、配额、重置、快照、cron 锁、TC、迁移、回滚、卸载和 Telegram/企业微信。
对于接受 root 脚本和本地配置的运维者，它可能更直接。

Guardian 面向集中管理：非 root Agent、mTLS、带时效签名任务、RBAC、独立审批、
只追加审计/重置事件、PostgreSQL 历史、有上限聚合、Web 工作流、集中告警状态及
备份恢复。网络 helper 不保存通知 Secret，也不以 cron 作为事实来源。

当前实测仅包括本地单元正确性和测试运行时间。真实 nftables/TC 吞吐、0/1/10/64
策略资源、重启恢复及双 VPS 行为必须等隔离 Linux Staging；本文不声称“全面超越”。
