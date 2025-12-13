# ARouter

ARouter 为搭建一个安全可靠的数据传输网络，防止中间人拦截。

## 主要特性
- 中间节点端口重复利用，只需要一个端口即可承载多个入口/出口。
- 支持 TCP/UDP 双协议入口/出口，单节点可同时承载多个入口/出口。
- 支持多节点组网，节点间可互为入口/出口。
- 支持多线路配置，提升网络可用性与性能。
- 节点间链路探测与动态/手动路由切换，支持多线路自动降级/切换。
- 支持 QUIC/WSS 数据平面，入口/出口可灵活配置，压缩可选。
- 动态加密策略，提高数据安全性

## 未来规划
- 支持更多传输协议，提升网络适应性
- 优化控制台用户体验，简化配置流程

## 部署：后端（控制器）

### SQLite 版本（快速起步）
```yaml
# docker-compose.yml
version: '3.8'
services:
  controller:
    image: 24802117/arouter:latest
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

### MySQL 版本（含 MySQL 容器，一键复制）
```yaml
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    container_name: arouter-mysql
    environment:
      - MYSQL_DATABASE=arouter
      - MYSQL_USER=arouter
      - MYSQL_PASSWORD=arouter123
      - MYSQL_ROOT_PASSWORD=change_me_root
    command: --default-authentication-plugin=mysql_native_password
    volumes:
      - ./mysql-data:/var/lib/mysql
    ports:
      - "3306:3306"
    restart: unless-stopped

  controller:
    image: 24802117/arouter:latest
    container_name: arouter-controller
    environment:
      - CONTROLLER_ADDR=:8080
      - DB_DSN=arouter:arouter123@tcp(mysql:3306)/arouter?parseTime=true&charset=utf8mb4&loc=Local
    depends_on:
      - mysql
    volumes:
      - ./certs:/app/certs   # 如需自定义证书
    ports:
      - "8080:8080"
    restart: unless-stopped
```
复制上述文件为 `docker-compose.yml`，`docker-compose up -d` 即可：会同时拉起 MySQL 与控制器。第一次启动会自动建表（AutoMigrate）。

如已有 MySQL，可仅保留 `controller` 服务，确保 `DB_DSN` 中的账号拥有建库/建表权限，并在 DSN 中加上 `?parseTime=true&charset=utf8mb4&loc=Local`。

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
- **加密策略**：控制台首页 → “全局设置”卡片 → “加密策略”区：
  1. 点击 “+ 增加策略”，填入 `ID`（整数标识）、`名称`（可选）、`算法`（AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305）、`密钥(Base64/HEX)`。
  2. 保存后控制器会自动校验/生成合规密钥并下发；节点拉取配置后按“当前时间秒 % 策略数”选用一条，入口加密、出口按 `enc_id` 解密，中间节点仅透传。
  3. 如果留空或长度不符，控制器会自动生成随机密钥，无需手填。

## 运行状态与系统信息
节点周期上报：CPU、内存、网络流量、运行时长、版本、OS/架构、链路 RTT/丢包；控制台卡片显示最新状态。

## 常用排查
- 服务未监听：检查 systemd/launchctl 状态，查看安装目录下 `arouter.log`、`arouter.err`。
- TLS/WSS 探测失败：确认目标端口是否启用 TLS，必要时切回 `ws`，或开启 `insecure_skip_tls`/留空 SNI。
- 重启：macOS `sudo launchctl kickstart -k system/com.arouter.node`；Linux `sudo systemctl restart arouter`。
