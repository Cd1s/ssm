# ssm

面向 agent 的无头 SSH 管理器。SSH 主机信息保存在本机加密 vault 中，同步时只上传和下载加密后的数据，真正的 SSH 连接始终从当前机器发起。

[中文](README.md) | [English](README.en.md)

## 安装

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

安装脚本会从 `Cd1s/ssm` 下载当前系统匹配的程序，安装到 `/usr/local/bin/ssm`，并创建 `/usr/local/bin/sshctl -> /usr/local/bin/ssm`。`sshctl` 不是额外脚本，它和 `ssm` 是同一个二进制。

## 常用命令

```bash
sshctl status
sshctl list --json
sshctl sync
sshctl doctor <alias> --deep --json     # vault + 连通 + 远端健康
sshctl check <alias>

# 单机（多参数自动 quote；连接默认复用）
sshctl run <alias> hostname
sshctl run <alias> --json hostname
sshctl plan <alias> bash -c 'echo hi'   # 干跑：remote_command + risk，不连机
sshctl run <alias> --secret API_KEY=@./key.txt -- printenv API_KEY
sshctl run <alias> -s <<'EOF'
echo "any quotes fine"
EOF

# 并行：多机 / 多脚本（舰队）
sshctl map limee-hk,aws-sg -j 8 hostname
sshctl map 'limee-*' --json uname -s
sshctl map host1,host2 --scripts a.sh,b.sh   # 每台×每个脚本并行
sshctl run host --scripts a.sh,b.sh          # 单机多脚本并行

# 文件与目录树
sshctl put <alias> ./dir /remote/dir
sshctl get <alias> /remote/dir ./dir

# 迁移后旧名软链
sshctl redirect set old-alias limee-hk
sshctl run old-alias hostname

sshctl push
```

连接失败 stderr：`ssm: error=dial_timeout|host_key_mismatch|alias_not_found|...`，退出码 **255**。默认 **连接复用**（`SSM_REUSE=0` / `--no-reuse` 关闭）。

### Agent 舰队：map 并行

| 命令 | 含义 |
|------|------|
| `sshctl map a,b,c -j 8 cmd` | 最多 8 路并行在 a/b/c 上跑同一命令 |
| `sshctl map 'web-*' hostname` | shell 风格 glob 选 alias |
| `sshctl map h --scripts s1.sh,s2.sh` | 单机多脚本并行 |
| `sshctl map a,b --scripts s1,s2` | host×script 笛卡尔积并行 |
| `sshctl map ... --plan` | 只展开目标与命令，不执行 |
| `sshctl map ... --json` | 结果数组：`ok/exit/stdout/error/latency_ms` |

某一台失败**不会**丢掉其它机器的结果；最终 exit 在有失败时非 0。

### 远程命令与引号

| 写法 | 行为 | 适用 |
|------|------|------|
| `sshctl run host cmd arg1 arg2` | 每个参数 shell 转义后拼接 | 短命令、`bash -c` |
| `sshctl run host -s <<'EOF'` | stdin 脚本 | 多行任意引号 |
| `sshctl run host --json cmd` | 结构化结果 | agent 解析 |
| `sshctl plan host cmd` | 干跑 + risk | 确认再执行 |
| `sshctl run host --secret K=v cmd` | 密钥作远端 env，trace 脱敏 | 密钥不进 argv 展示 |

## 可选同步

你可以自己部署一个中心服务器，用来在多台机器之间同步加密后的 vault：

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

中心服务器只保存加密 vault blob，不解密 SSH 密码或私钥。`sshctl list/run/shell/status` 和 `ssm list/exec/shell` 会在读取 vault 前检测远端 ETag；远端有新版本时会自动拉取。本地新增、编辑、删除连接后默认自动推送；也可以手动执行 `sshctl push`。

## 中心服务器

```bash
ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
```

推荐放在你自己的 HTTPS 反向代理后面：

```text
<sync-server-url> -> 127.0.0.1:18787
```

systemd 示例：

```ini
[Unit]
Description=SSM encrypted sync server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## Agent 一键提示词

把下面内容发给另一台机器上的 agent：

```text
从 Cd1s/ssm 安装 SSM：
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh

如果已有同步配置，把 master.pass 和 cloud.json 放到 /root/.config/ssm，并执行 chmod 600。
然后执行 sshctl sync，用 sshctl status 和 sshctl list 验证。
连接服务器优先用 sshctl run <alias> <command...> 或多行 sshctl run <alias> -s <<'EOF' ... EOF（少踩引号坑）。
也可用 sshctl shell <alias>、sshctl put <alias> <local> <remote>。
```

项目内 agent skill 在 `skills/agent-ssm/SKILL.md`。

## 自动更新

`1.0.0` 起默认从 `Cd1s/ssm` 检查 GitHub 最新 release。发现更高版本时会替换当前程序。手动更新：

```bash
ssm update
```

无头测试、离线环境或不希望程序启动时触网时，可以禁用 release 检查：

```bash
SSM_UPDATE_REPO=off ssm --version
```
