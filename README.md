# CCGuard

适用于 macOS 的 Claude 终端辅助工具：检查当前网络出口，确认后启动 Claude CLI / Desktop，以及正常退出后清理残留进程。这个仓库 `lib-fuxx-claude` 是实现和安装包的源码入口。

只使用 Python 标准库，无需 `pip install`。安装后的程序是独立副本，不依赖仓库或原工作区路径；也不会安装 Claude、复制账号或迁移聊天记录。

## 四个命令

| 命令 | 行为 |
| --- | --- |
| `ccguard-check` | 只运行网络检查，输出结果并返回检查状态；不询问、不操作 Claude。 |
| `ccguard-cli [参数…]` | 网络检查结束后询问 `[y/N]`，输入 `y` 才启动 CLI，参数和当前目录保持不变。 |
| `ccguard-desktop [参数…]` | 网络检查结束后询问 `[y/N]`，输入 `y` 才启动 Desktop。 |
| `ccguard-kill` | 请求正常退出，清理已识别的残留进程，并复核进程和后台状态。 |

启动时即使检查出现报错或警告，仍由你看完结果后决定；回车默认不启动。检查被中断或程序异常退出时取消启动。

## 安装

需要 **macOS、Python 3.9 或以上版本**。启动对应客户端前，请另外安装 Claude 原生 CLI 或 Claude Desktop；单独检查网络不需要安装 Claude。

```sh
git clone https://github.com/QingC2206/lib-fuxx-claude.git
cd lib-fuxx-claude
bash install.sh
```

安装只复制程序和设置 PATH，不执行网络检查，也不启动或关闭 Claude。用普通用户安装，不需要 `sudo`。安装完成后新开终端窗口，或在当前窗口执行：

```sh
export PATH="$HOME/.local/bin:$PATH"
rehash  # zsh 刷新命令缓存
```

可指定一个长期保留的 Python；安装器会记录它的绝对路径，之后不需要激活同一个 Conda/虚拟环境：

```sh
CCGUARD_PYTHON=/你的/python3/路径 bash install.sh
```

自定义安装位置或自行管理 PATH：

```sh
bash install.sh --prefix "$HOME/.local" --no-path
```

默认安装结构：

```text
~/.local/bin/ccguard-check     ─┐
~/.local/bin/ccguard-cli        │
~/.local/bin/ccguard-desktop    ├─> ~/.local/lib/ccguard/ccguard.py
~/.local/bin/ccguard-kill      ─┘                       └─> net_check.py
~/.local/lib/ccguard/manifest.json    文件校验和、Python 路径及 PATH 记录
```

终端通过 PATH 找到四个 Shell 入口，再调用已安装的 Python 程序。删除下载的源码或解压目录不影响已安装命令。安装器支持 zsh 的 `.zshrc` 和 bash 的 `.bash_profile`，仅管理自己的 PATH 区块。

## 从旧命令迁移

在已有旧版分发包的 Mac 上直接运行 `bash install.sh`，自动迁移为：

| 旧命令 | 新命令 |
| --- | --- |
| `fuck-claude-check` | `ccguard-check` |
| `fuck-claude-cli` | `ccguard-cli` |
| `fuck-claude-desktop` | `ccguard-desktop` |
| `kill-claude` | `ccguard-kill` |

迁移支持 `~/.local/lib/claude-tools/manifest.json` 管理的三命令或四命令旧包。安装器先检查旧清单、文件校验和、Shell 配置和新命令是否冲突，再备份到 `~/.local/state/ccguard/backups/`。新程序全部写入后才移除旧命令及已登记的旧程序文件，并替换原 PATH 区块，不保留旧命令别名。

备份中的 `backup.json` 记录原路径、备份文件、权限和 SHA-256，可用于手动恢复。写入或删除失败时，安装器会尝试回滚本次已完成的改动；备份仍保留。旧目录里的额外文件不会被删除。

旧文件有本地修改、旧命令缺少清单、符号链接或同名冲突时，安装器保留原文件并停止，不自动覆盖个人修改。旧版登记了 PATH 区块时，迁移需使用同一 Shell 配置，不可加 `--no-path`。

## 网络检查

```sh
ccguard-check
ccguard-check --json
ccguard-check --timeout 6 --dns-samples 3
ccguard-check --proxy http://127.0.0.1:7890
ccguard-check --help
```

默认显示四项结果，异常项展开原因：

| 检查项 | 检查范围 |
| --- | --- |
| 出口 IP 与归属 | HTTP/HTTPS 路径采样得到的出口 IP 和地域。 |
| STUN / ICE | UDP STUN 采样，以及通过 `--candidate` 附加的 ICE 地址样本。 |
| IPv6 | 本机 IPv6 路由和默认/代理路径的 IPv6 出口。 |
| DNS 解析器 | 通过 IPLeak 随机域名采样实际递归解析器，再核验 IP 归属。 |

**内置地域规则是个人策略：US 正常，CN/HK 报错，其他地域或证据不足警告。**

| 状态 | `ccguard-check` 返回码 |
| --- | --- |
| `PASS`，全部正常 | `0` |
| `FAIL`，至少一项报错 | `1` |
| `WARN`，有警告且没有报错 | `2` |

IPv6 按“路由器已关闭 IPv6”的个人设置处理：本机明确无 IPv6 路由、且未测得 IPv6 出口时正常；若实际观测到出口，仍按地域规则判断。不同设备如需不同策略，应在安装前调整源码；安装后直接修改的文件会受到更新冲突保护。

这些结果只代表本次采样，不保证浏览器、所有应用或后续网络状态一致，也不代表 Claude 服务一定接受该出口。脚本不自动采集浏览器 ICE 或独立安全 DNS；DoH 查询仅作辅助诊断。DNS 采样不使用 HTTP 代理，仍受系统解析和 TUN 路由影响。检查会访问第三方 IP、DNS 和 STUN 服务。

`--timeout` 是每次网络操作的超时，不是整次检查的总时限；JSON 报告使用 `schema_version=3`。

## 启动 Claude

```sh
ccguard-cli
ccguard-cli --resume
ccguard-cli -- --help  # 把 --help 交给 Claude CLI，仍先检查和确认
ccguard-desktop
```

CLI 通过 PATH 寻找 `claude`。Desktop 验证应用包标识，默认查找 `/Applications/Claude.app`、`~/Applications/Claude.app` 和 Spotlight 登记的应用；自定义位置可设置：

```sh
export CLAUDE_DESKTOP_APP="/其他位置/Claude.app"
```

这两个命令的参数传给 Claude，不传给网络检查。要调整检查选项，请单独使用 `ccguard-check`。

## 退出与后台提示

```sh
ccguard-kill
ccguard-kill --dry-run  # 只读预览对象及后台状态，不发退出请求或信号
```

桌面版先请求正常退出，CLI 先收到 SIGTERM；等待 5 秒仍有残留时强制清理，并在后续 8 秒内处理重新出现的进程。结束前须连续 3 秒未检出相关进程；若期限刚到时进程消失，会补足观察时间。

清理只针对当前用户已核验的 Claude 原生 CLI、桌面应用、子进程和 macOS 标记归属于它的助手。每次发信号前重新核验进程身份，不按 `node` 等通用名字批量杀进程。后台读取完成后还会再查一次进程。

只有 `ccguard-kill` 显示后台权限状态。开启时提示：

> ⚠️⚠️⚠️ Claude 的后台权限处于开启状态，建议从「系统设置 → 通用 → 登录项与扩展 → App 后台活动」中关闭 Claude。

已关闭时显示 `[OK] 后台任务权限: 已关闭`。这是文字提醒，不增加菜单、不打开系统设置、不改权限；“允许后台”本身不等于当前有进程运行，也不会单独改变返回码。

| `ccguard-kill` 返回码 | 含义 |
| --- | --- |
| `0` | 观察范围内未检出进程，相关服务未报告运行 PID。 |
| `1` | 仍有已识别残留，或操作失败。 |
| `2` | 后台读取失败、归属未确认、其他用户进程或服务状态需核实。 |

macOS 可以在应用退出后保留后台任务，见 [Apple 说明](https://support.apple.com/en-us/125671)。归属检查使用 macOS 非公开接口，权限读取依赖 `sfltool dumpbtm`；接口不可用、读取超时或格式无法识别时保留警告。短时观察不能保证应用以后不会被其他任务重新启动。

## 更新、分发与卸载

从仓库更新：

```sh
git pull --ff-only
bash install.sh
```

再次安装不会重复添加 PATH，也不会覆盖未登记的同名文件或安装后手动修改的文件。

生成可复制到其他 Mac 的完整 ZIP（包含源码、测试和说明，不含本机路径、备份或账号）：

```sh
python3 -B build_release.py
```

输出为 `dist/ccguard-macos.zip` 和 `dist/ccguard-macos.zip.sha256`。目标 Mac 解压后进入 `ccguard` 文件夹，执行 `bash install.sh`。可在 ZIP 所在目录校验：

```sh
shasum -a 256 -c ccguard-macos.zip.sha256
```

卸载：

```sh
bash uninstall.sh
# 或在源码目录已删除时：
python3 "$HOME/.local/lib/ccguard/install.py" --uninstall
```

只移除登记且未被修改的工具文件及 PATH 区块；额外文件、迁移备份、Claude 应用及账号数据保留。

## 开发与测试

```sh
python3 -B -m unittest discover -s tests -q
```

测试替换网络访问、进程列表、启动/退出调用和信号；安装与迁移测试仅操作临时目录。测试不会实际执行四个入口命令，也不会启动或关闭 Claude。支持范围是 macOS，未适配 Windows/Linux。

源码入口：`ccguard.py` 管理命令流程，`net_check.py` 执行网络诊断，`install.py` 管理安装/迁移/卸载，`build_release.py` 生成分发包。许可证：[MIT](LICENSE)。
