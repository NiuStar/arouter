# ARouter

ARouter 为搭建一个安全可靠的数据传输网络，防止中间人拦截。

## 主要特性
- 中间节点端口重复利用，只需要一个端口即可承载多个入口/出口。
- 支持 TCP/UDP 双协议入口/出口，单节点可同时承载多个入口/出口。
- 支持多节点组网，节点间可互为入口/出口。
- 支持多线路配置，提升网络可用性与性能。
- 节点间链路探测与动态/手动路由切换，支持多线路自动降级/切换。
- 支持 QUIC/WSS 数据平面，入口/出口可灵活配置，压缩可选。

## 未来规划
- 增加动态加密策略，提高数据安全性
- 支持更多传输协议，提升网络适应性
- 优化控制台用户体验，简化配置流程

## 部署：后端（控制器）

### SQLite 版本（快速起步）
```yaml
# docker-compose.yml
version: '3.8'
services:
  controller:
    image: your-registry/arouter-controller:latest
    container_name: arouter-controller
    environment:
      - CONTROLLER_ADDR=:8080
      - DB_PATH=/data/arouter.db
    volumes:
      - ./data:/data
      - ./certs:/app/certs   # 如需自定义证书
    ports:
      - "8080:8080"   # 控制器 API/前端
    restart: unless-stopped
```
启动：`docker-compose up -d`，访问 `http://<host>:8080`。

### MySQL 版本
```yaml
version: '3.8'
services:
  controller:
    image: your-registry/arouter-controller:latest
    container_name: arouter-controller
    environment:
      - CONTROLLER_ADDR=:8080
      - DB_DSN=user:pass@tcp(mysql:3306)/arouter?parseTime=true
    volumes:
      - ./certs:/app/certs
    ports:
      - "8080:8080"
    restart: unless-stopped
```
确保 MySQL 已建库 `arouter` 且账号具备建表权限（控制器会 AutoMigrate）。

## 节点部署
1. 在控制台创建节点（“节点列表”→“新建节点”），记录节点 Token。
2. 在目标机执行控制台提供的安装命令，形如：
   ```
   curl -fsSL http://<controller>:8080/nodes/<id>/install.sh?token=<nodeToken> | bash -s -- -k <nodeToken>
   ```
   - macOS 默认安装到 `~/.arouter`，使用 launchctl 自启。
   - Linux 默认安装到 `/opt/arouter`，使用 systemd 自启。
3. 节点启动后定期拉取配置/证书，并上报状态。

## 基本配置操作（控制台）
- **添加入口 (Entry)**：节点详情 → “入口” → “添加入口”，填写 `listen`、`proto` (`tcp/udp/both`)、`exit`、`remote`。
- **添加对端 (Peer)**：节点详情 → “对端” → “添加对端”，填写对端节点名、监听地址（控制器自动按传输拼协议）。
- **添加线路 (Route)**：节点详情 → “线路” → “添加线路”，选择路径节点顺序和优先级；同一出口可多条线路，按优先级自动切换。
- **多线路优势**：主线路异常时自动降级/切换，提高可用性和性能；可人为指定优先级。

## 运行状态与系统信息
节点周期上报：CPU、内存、网络流量、运行时长、版本、OS/架构、链路 RTT/丢包；控制台卡片显示最新状态。

## 常用排查
- 服务未监听：检查 systemd/launchctl 状态，查看安装目录下 `arouter.log`、`arouter.err`。
- TLS/WSS 探测失败：确认目标端口是否启用 TLS，必要时切回 `ws`，或开启 `insecure_skip_tls`/留空 SNI。
- 重启：macOS `sudo launchctl kickstart -k system/com.arouter.node`；Linux `sudo systemctl restart arouter`。

