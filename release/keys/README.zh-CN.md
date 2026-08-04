# Alpha Release 签名信任锚

`v0.4-alpha-release-ed25519.pem` 是 VPS Guardian v0.4 Alpha 发布线使用的
Ed25519 公钥信任锚：

- Key ID：`ed25519-sha256:3e3d878e37f3ababd96827441be8dae17bb397b8012e8f7de65331f2356e524a`
- PEM SHA-256：`c9fe05398821dc580aaebcda4cea64f7bf9c998dc59c898b4fcdf79aacec37b4`

对应私钥保存在仓库外，仅密钥保管人可以读取。这是一把用于
Alpha/Developer Preview 的发布签名密钥，不是离线 Production 签名密钥。
每个发布清单都必须绑定明确版本，在仓库外完成签名，并在公开发布前使用
这里的公钥重新验证。

轮换时必须先通过代码审查加入新公钥和 Key ID。只有在明确记录的过渡期内，
安装器才可以同时接受两把经过审查的公钥；旧公钥必须在过渡期结束后的后续
受审发布中移除。私钥禁止进入 Git、CI 制品、日志、命令输出、容器镜像或
公开 Release 资产。
