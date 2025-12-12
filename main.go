package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	http2 "alicode.mukj.cn/yjkj.ink/work/http"
	"github.com/quic-go/quic-go"
	"nhooyr.io/websocket"
)

var buildVersion = "dev"

// 该版本实现了基础的 WSS 数据平面、JSON 配置加载、动态选路和简单的 RTT 探测。
// 多跳通过 WebSocket 级联，出口节点将流量转发到 RemoteAddr。

type (
	NodeID   string
	Protocol string
)

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// EntryPort maps a local port to a destination node and final remote address.
type EntryPort struct {
	ListenAddr string   // local address e.g. ":10080"
	Proto      Protocol // tcp or udp
	ExitNode   NodeID   // target node that knows how to reach RemoteAddr
	RemoteAddr string   // remote IP:port to dial at the exit
}

// LinkMetrics describes current link health.
type LinkMetrics struct {
	RTT       time.Duration
	LossRatio float64 // 0..1
	UpdatedAt time.Time
}

// Topology keeps weighted edges in-memory.
type Topology struct {
	mu    sync.RWMutex
	edges map[NodeID]map[NodeID]LinkMetrics
}

func NewTopology() *Topology {
	return &Topology{edges: make(map[NodeID]map[NodeID]LinkMetrics)}
}

func (t *Topology) Set(from, to NodeID, m LinkMetrics) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.edges[from] == nil {
		t.edges[from] = make(map[NodeID]LinkMetrics)
	}
	t.edges[from][to] = m
}

func (t *Topology) Snapshot() map[NodeID]map[NodeID]LinkMetrics {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[NodeID]map[NodeID]LinkMetrics, len(t.edges))
	for from, row := range t.edges {
		copyRow := make(map[NodeID]LinkMetrics, len(row))
		for to, m := range row {
			copyRow[to] = m
		}
		out[from] = copyRow
	}
	return out
}

// Metrics 以原子计数记录流量与会话情况，暴露 /metrics 供采集。
type Metrics struct {
	tcpSessions int64
	udpSessions int64
	bytesUp     int64
	bytesDown   int64
}

func (m *Metrics) IncTCP()         { atomic.AddInt64(&m.tcpSessions, 1) }
func (m *Metrics) IncUDP()         { atomic.AddInt64(&m.udpSessions, 1) }
func (m *Metrics) AddUp(n int64)   { atomic.AddInt64(&m.bytesUp, n) }
func (m *Metrics) AddDown(n int64) { atomic.AddInt64(&m.bytesDown, n) }

// NodeStatus 描述节点自身运行状态，用于上报给控制器。
type NodeStatus struct {
	CPUUsage    float64  `json:"cpu_usage"`       // 0-100
	MemUsed     uint64   `json:"mem_used_bytes"`  // 已用内存
	MemTotal    uint64   `json:"mem_total_bytes"` // 总内存
	UptimeSec   uint64   `json:"uptime_sec"`
	NetInBytes  uint64   `json:"net_in_bytes"`
	NetOutBytes uint64   `json:"net_out_bytes"`
	Version     string   `json:"version"`
	Transport   string   `json:"transport"`
	Compression string   `json:"compression"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	PublicIPs   []string `json:"public_ips"`
}

func (m *Metrics) Serve(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "tcp_sessions_total %d\n", atomic.LoadInt64(&m.tcpSessions))
		fmt.Fprintf(w, "udp_sessions_total %d\n", atomic.LoadInt64(&m.udpSessions))
		fmt.Fprintf(w, "bytes_up_total %d\n", atomic.LoadInt64(&m.bytesUp))
		fmt.Fprintf(w, "bytes_down_total %d\n", atomic.LoadInt64(&m.bytesDown))
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server stopped: %v", err)
		}
	}()
	return srv
}

// Router picks a path using the latest metrics.
type Router struct {
	Topology *Topology
}

func (r *Router) BestPath(src, dst NodeID) ([]NodeID, error) {
	graph := r.Topology.Snapshot()
	dist := make(map[NodeID]float64)
	prev := make(map[NodeID]NodeID)
	unseen := make(map[NodeID]bool)

	for from := range graph {
		unseen[from] = true
		dist[from] = 1e18
		for to := range graph[from] {
			unseen[to] = true
			if _, ok := dist[to]; !ok {
				dist[to] = 1e18
			}
		}
	}
	if len(unseen) == 0 {
		return nil, errors.New("empty topology")
	}
	if _, ok := dist[src]; !ok {
		return nil, fmt.Errorf("source %s not present", src)
	}
	dist[src] = 0

	weight := func(m LinkMetrics) float64 {
		rtt := float64(m.RTT.Milliseconds())
		if rtt <= 0 {
			rtt = 1
		}
		loss := m.LossRatio
		return rtt * (1 + loss*2) // penalize loss heavier than latency
	}

	for len(unseen) > 0 {
		var u NodeID
		best := 1e18
		for n := range unseen {
			if dist[n] < best {
				best = dist[n]
				u = n
			}
		}
		delete(unseen, u)
		for v, metrics := range graph[u] {
			alt := dist[u] + weight(metrics)
			if alt < dist[v] {
				dist[v] = alt
				prev[v] = u
			}
		}
	}

	// reconstruct
	path := []NodeID{dst}
	for at := dst; at != src; {
		p, ok := prev[at]
		if !ok {
			return nil, fmt.Errorf("no route %s -> %s", src, dst)
		}
		path = append([]NodeID{p}, path...)
		at = p
	}
	return path, nil
}

func fmtVal(v float64) string {
	if math.IsInf(v, 1) {
		return "inf"
	}
	return fmt.Sprintf("%.2f", v)
}

type cpuSnapshot struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
	total                                                 uint64
}

var (
	prevCPUSnap cpuSnapshot
	hasCPUSnap  bool
)

func readCPUSnapshot() (cpuSnapshot, error) {
	if runtime.GOOS == "darwin" {
		return readCPUSnapshotDarwin()
	}
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSnapshot{}, err
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var snap cpuSnapshot
		parse := func(idx int) uint64 {
			if idx >= len(fields) {
				return 0
			}
			v, _ := strconv.ParseUint(fields[idx], 10, 64)
			return v
		}
		snap.user = parse(1)
		snap.nice = parse(2)
		snap.system = parse(3)
		snap.idle = parse(4)
		snap.iowait = parse(5)
		snap.irq = parse(6)
		snap.softirq = parse(7)
		snap.steal = parse(8)
		snap.total = snap.user + snap.nice + snap.system + snap.idle + snap.iowait + snap.irq + snap.softirq + snap.steal
		return snap, nil
	}
	return cpuSnapshot{}, fmt.Errorf("cpu line not found in /proc/stat")
}

// readCPUSnapshotDarwin 通过 sysctl kern.cp_time 获取 CPU 时间片。
func readCPUSnapshotDarwin() (cpuSnapshot, error) {
	out, err := exec.Command("sysctl", "-n", "kern.cp_time").Output()
	if err != nil {
		return cpuSnapshot{}, err
	}
	fields := strings.Fields(string(bytes.TrimSpace(out)))
	if len(fields) < 5 {
		return cpuSnapshot{}, fmt.Errorf("unexpected kern.cp_time: %s", string(out))
	}
	parse := func(idx int) uint64 {
		if idx >= len(fields) {
			return 0
		}
		v, _ := strconv.ParseUint(fields[idx], 10, 64)
		return v
	}
	var snap cpuSnapshot
	snap.user = parse(0)
	snap.nice = parse(1)
	snap.system = parse(2)
	// macOS 第4个是 idle，第5个是 intr
	snap.idle = parse(3)
	snap.irq = parse(4)
	snap.total = snap.user + snap.nice + snap.system + snap.idle + snap.irq
	return snap, nil
}

// readCPUPercentDarwin 优先解析 top 的 CPU usage 行，失败则用 ps 汇总/核数。
func readCPUPercentDarwin() (float64, error) {
	out, err := exec.Command("top", "-l", "1", "-n", "0").Output()
	if err == nil {
		re := regexp.MustCompile(`CPU usage:\s*([\d\.]+)% user,\s*([\d\.]+)% sys`)
		if m := re.FindStringSubmatch(string(out)); len(m) == 3 {
			u, _ := strconv.ParseFloat(m[1], 64)
			s, _ := strconv.ParseFloat(m[2], 64)
			return u + s, nil
		}
	}
	// fallback: ps 汇总再按核数归一化
	psOut, err2 := exec.Command("ps", "-A", "-o", "%cpu").Output()
	if err2 != nil {
		return 0, err2
	}
	lines := strings.Split(string(psOut), "\n")
	var sum float64
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "%CPU") {
			continue
		}
		if v, err := strconv.ParseFloat(l, 64); err == nil {
			sum += v
		}
	}
	cpus := float64(runtime.NumCPU())
	if cpus > 0 {
		sum = sum / cpus
	}
	if sum > 100 {
		sum = 100
	}
	return sum, nil
}

func readMem() (used, total uint64, err error) {
	if runtime.GOOS == "darwin" {
		return readMemDarwin()
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	var memTotal, memAvail uint64
	for _, l := range lines {
		if strings.HasPrefix(l, "MemTotal:") {
			fmt.Sscanf(l, "MemTotal: %d kB", &memTotal)
		} else if strings.HasPrefix(l, "MemAvailable:") {
			fmt.Sscanf(l, "MemAvailable: %d kB", &memAvail)
		}
	}
	total = memTotal * 1024
	if memAvail > 0 {
		used = (memTotal - memAvail) * 1024
	}
	return
}

func readUptime() (uint64, error) {
	if runtime.GOOS == "darwin" {
		return readUptimeDarwin()
	}
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	var up float64
	if _, err := fmt.Sscanf(string(bytes.TrimSpace(data)), "%f", &up); err != nil {
		return 0, err
	}
	return uint64(up), nil
}

func readNet() (rx, tx uint64, err error) {
	if runtime.GOOS == "darwin" {
		return readNetDarwin()
	}
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		if !strings.Contains(l, ":") {
			continue
		}
		parts := strings.Split(strings.TrimSpace(l), ":")
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += rxBytes
		tx += txBytes
	}
	return
}

func readMemDarwin() (used, total uint64, err error) {
	// total from hw.memsize
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err == nil {
		outStr := strings.TrimSpace(string(out))
		total, _ = strconv.ParseUint(outStr, 10, 64)
	}
	pageSize := uint64(4096)
	cmd := exec.Command("vm_stat")
	vmOut, vmErr := cmd.Output()
	if vmErr != nil {
		return used, total, vmErr
	}
	lines := strings.Split(string(vmOut), "\n")
	reNum := regexp.MustCompile(`([0-9]+)`)
	freePages := uint64(0)
	inactivePages := uint64(0)
	specPages := uint64(0)
	for _, l := range lines {
		if strings.Contains(l, "page size of") {
			if matches := reNum.FindStringSubmatch(l); len(matches) > 1 {
				if ps, err := strconv.ParseUint(matches[1], 10, 64); err == nil {
					pageSize = ps
				}
			}
		}
		if strings.HasPrefix(strings.TrimSpace(l), "Pages free") {
			if matches := reNum.FindStringSubmatch(l); len(matches) > 1 {
				freePages, _ = strconv.ParseUint(matches[1], 10, 64)
			}
		}
		if strings.HasPrefix(strings.TrimSpace(l), "Pages inactive") {
			if matches := reNum.FindStringSubmatch(l); len(matches) > 1 {
				inactivePages, _ = strconv.ParseUint(matches[1], 10, 64)
			}
		}
		if strings.HasPrefix(strings.TrimSpace(l), "Pages speculative") {
			if matches := reNum.FindStringSubmatch(l); len(matches) > 1 {
				specPages, _ = strconv.ParseUint(matches[1], 10, 64)
			}
		}
	}
	freeBytes := (freePages + inactivePages + specPages) * pageSize
	if total > freeBytes {
		used = total - freeBytes
	}
	return used, total, nil
}

func readUptimeDarwin() (uint64, error) {
	out, err := exec.Command("sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return 0, err
	}
	// format: { sec = 1700000000, usec = 0 } ...
	re := regexp.MustCompile(`sec\s*=\s*([0-9]+)`)
	m := re.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return 0, fmt.Errorf("boottime parse failed")
	}
	sec, _ := strconv.ParseUint(m[1], 10, 64)
	if sec == 0 {
		return 0, fmt.Errorf("boottime zero")
	}
	now := uint64(time.Now().Unix())
	if now > sec {
		return now - sec, nil
	}
	return 0, fmt.Errorf("invalid boottime")
}

func readNetDarwin() (rx, tx uint64, err error) {
	out, err := exec.Command("netstat", "-ibn").Output()
	if err != nil {
		return rx, tx, err
	}
	lines := strings.Split(string(out), "\n")
	seen := make(map[string]bool)
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 12 || fields[0] == "Name" {
			continue
		}
		iface := fields[0]
		if strings.HasPrefix(iface, "lo") {
			continue
		}
		key := iface
		if seen[key] {
			continue
		}
		seen[key] = true
		rxBytes, _ := strconv.ParseUint(fields[10], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[11], 10, 64)
		rx += rxBytes
		tx += txBytes
	}
	return
}

func detectOSInfo() (string, string) {
	arch := runtime.GOARCH
	if runtime.GOOS == "darwin" {
		nameOut, _ := exec.Command("sw_vers", "-productName").Output()
		verOut, _ := exec.Command("sw_vers", "-productVersion").Output()
		name := strings.TrimSpace(string(nameOut))
		ver := strings.TrimSpace(string(verOut))
		if name == "" {
			name = "macos"
		}
		if ver != "" {
			name = name + " " + ver
		}
		return name, arch
	}
	// try /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		var name, version string
		for _, l := range lines {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				name = strings.Trim(l[len("PRETTY_NAME="):], `"`)
			} else if strings.HasPrefix(l, "NAME=") && name == "" {
				name = strings.Trim(l[len("NAME="):], `"`)
			} else if strings.HasPrefix(l, "VERSION_ID=") {
				version = strings.Trim(l[len("VERSION_ID="):], `"`)
			}
		}
		if name != "" && version != "" {
			return name + " " + version, arch
		}
		if name != "" {
			return name, arch
		}
	}
	return runtime.GOOS, arch
}

func gatherPublicIPs() []string {
	seen := make(map[string]struct{})
	for _, ip := range publicIPsFromInterfaces() {
		seen[ip] = struct{}{}
	}
	for _, ip := range []string{fetchPublicIPFromIPSB("tcp4"), fetchPublicIPFromIPSB("tcp6")} {
		if ip == "" {
			continue
		}
		seen[ip] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func publicIPsFromInterfaces() []string {
	ifaces, _ := net.Interfaces()
	var res []string
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || isPrivateOrLinkLocal(ip) {
				continue
			}
			res = append(res, ip.String())
		}
	}
	return res
}

func fetchPublicIPFromIPSB(network string) string {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Timeout: 4 * time.Second, Transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ip.sb", nil)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	ipStr := strings.TrimSpace(string(b))
	ip := net.ParseIP(ipStr)
	if ip == nil || isPrivateOrLinkLocal(ip) {
		return ""
	}
	return ip.String()
}

func isPrivateOrLinkLocal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 10 || v4[0] == 127 {
			return true
		}
		if v4[0] == 192 && v4[1] == 168 {
			return true
		}
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return true
		}
		return false
	}
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

func gatherNodeStatus() NodeStatus {
	status := NodeStatus{Version: buildVersion}
	status.OS, status.Arch = detectOSInfo()
	status.PublicIPs = gatherPublicIPs()

	if snap, err := readCPUSnapshot(); err == nil {
		if hasCPUSnap {
			idleDiff := float64(snap.idle - prevCPUSnap.idle)
			totalDiff := float64(snap.total - prevCPUSnap.total)
			if totalDiff > 0 {
				status.CPUUsage = (1 - idleDiff/totalDiff) * 100
			}
		}
		prevCPUSnap = snap
		hasCPUSnap = true
	} else if runtime.GOOS == "darwin" {
		// fallback: direct macOS CPU%
		if p, err := readCPUPercentDarwin(); err == nil {
			status.CPUUsage = p
		}
	}
	if used, total, err := readMem(); err == nil {
		status.MemUsed = used
		status.MemTotal = total
	}
	if up, err := readUptime(); err == nil {
		status.UptimeSec = up
	}
	if rx, tx, err := readNet(); err == nil {
		status.NetInBytes = rx
		status.NetOutBytes = tx
	}
	return status
}

func defaultIfEmpty(val, def string) string {
	if strings.TrimSpace(val) == "" {
		return def
	}
	return val
}

func (n *Node) recordMetric(peer NodeID, m LinkMetrics) {
	if n.ControllerURL == "" {
		return
	}
	n.metricsMu.Lock()
	defer n.metricsMu.Unlock()
	if n.lastMetrics == nil {
		n.lastMetrics = make(map[NodeID]LinkMetrics)
	}
	n.lastMetrics[peer] = m
}

func (n *Node) pushAndPullLoop(ctx context.Context) {
	interval := n.PollPeriod
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	if n.pushMetrics(ctx) {
		n.pullTopology(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n.pushMetrics(ctx) {
				n.pullTopology(ctx)
			}
		}
	}
}

func (n *Node) pushMetrics(ctx context.Context) bool {
	n.metricsMu.Lock()
	snapshot := make(map[NodeID]LinkMetrics, len(n.lastMetrics))
	for k, v := range n.lastMetrics {
		snapshot[k] = v
	}
	n.metricsMu.Unlock()
	payload := struct {
		From    NodeID                     `json:"from"`
		Metrics map[NodeID]LinkMetricsJSON `json:"metrics"`
		Status  NodeStatus                 `json:"status"`
	}{From: n.ID, Metrics: make(map[NodeID]LinkMetricsJSON, len(snapshot)), Status: gatherNodeStatus()}
	payload.Status.Transport = n.TransportMode
	payload.Status.Compression = n.Compression
	for k, v := range snapshot {
		payload.Metrics[k] = LinkMetricsJSON{RTTms: v.RTT.Milliseconds(), Loss: v.LossRatio, UpdatedAt: v.UpdatedAt}
	}
	data, _ := json.Marshal(payload)
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/metrics"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	if len(n.AuthKey) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(n.AuthKey))
	}
	if tok := n.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("push metrics failed: %v", err)
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if n.DebugLog {
		log.Printf("[metrics debug] payload=%s status=%s body=%s", string(data), resp.Status, string(body))
	}
	if resp.StatusCode >= 300 {
		log.Printf("push metrics non-2xx: %s body=%s", resp.Status, string(body))
	}
	return resp.StatusCode < 300
}

func (n *Node) pullTopologyLoop(ctx context.Context) {
	interval := n.TopologyPull
	if interval <= 0 {
		interval = n.PollPeriod
		if interval <= 0 {
			interval = time.Minute
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	n.pullTopology(ctx) // initial pull
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.pullTopology(ctx)
		}
	}
}

func (n *Node) pullRoutesLoop(ctx context.Context) {
	interval := n.RoutePull
	if interval <= 0 {
		interval = n.TopologyPull
	}
	if interval <= 0 {
		interval = n.PollPeriod
	}
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	n.pullRoutes(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.pullRoutes(ctx)
		}
	}
}

type topologyPayload struct {
	Edges map[NodeID]map[NodeID]LinkMetricsJSON `json:"edges"`
}

type LinkMetricsJSON struct {
	RTTms     int64     `json:"rtt_ms"`
	Loss      float64   `json:"loss"`
	UpdatedAt time.Time `json:"updated_at"`
}

type certPayload struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (n *Node) pullTopology(ctx context.Context) {
	if n.ControllerURL == "" {
		return
	}
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/topology"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if tok := n.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("pull topology failed: %v", err)
		return
	}
	defer resp.Body.Close()
	var payload topologyPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		log.Printf("decode topology failed: %v", err)
		return
	}
	for from, row := range payload.Edges {
		for to, jm := range row {
			n.Router.Topology.Set(from, to, LinkMetrics{
				RTT:       time.Duration(jm.RTTms) * time.Millisecond,
				LossRatio: jm.Loss,
				UpdatedAt: jm.UpdatedAt,
			})
			n.recordMetric(to, LinkMetrics{
				RTT:       time.Duration(jm.RTTms) * time.Millisecond,
				LossRatio: jm.Loss,
				UpdatedAt: jm.UpdatedAt,
			})
		}
	}
}

func (n *Node) fetchCertLoop(ctx context.Context) {
	if n.ControllerURL == "" || n.CertPath == "" || n.KeyPath == "" {
		return
	}
	interval := n.TopologyPull
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	n.fetchCert(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.fetchCert(ctx)
		}
	}
}

func (n *Node) fetchCert(ctx context.Context) {
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/certs"
	log.Printf("[config] fetching cert from %s", url)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if tok := n.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[config] fetch cert failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[config] fetch cert non-2xx: %s body=%s", resp.Status, string(body))
		return
	}
	var payload certPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		log.Printf("[config] decode cert payload failed: %v", err)
		return
	}
	if payload.Cert == "" || payload.Key == "" {
		log.Printf("[config] cert payload empty")
		return
	}
	ensureDir := func(path string) error {
		dir := filepath.Dir(path)
		if dir == "" || dir == "." {
			return nil
		}
		return os.MkdirAll(dir, 0700)
	}
	if err := ensureDir(n.CertPath); err != nil {
		log.Printf("[config] ensure cert dir failed: %v", err)
		return
	}
	if err := ensureDir(n.KeyPath); err != nil {
		log.Printf("[config] ensure key dir failed: %v", err)
		return
	}
	if err := os.WriteFile(n.CertPath, []byte(payload.Cert), 0600); err != nil {
		log.Printf("[config] write cert failed: %v", err)
		return
	}
	if err := os.WriteFile(n.KeyPath, []byte(payload.Key), 0600); err != nil {
		log.Printf("[config] write key failed: %v", err)
		return
	}
	log.Printf("[config] updated cert/key from controller -> cert=%s key=%s", n.CertPath, n.KeyPath)
}

type routesPayload struct {
	Routes []routePlanConfig `json:"routes"`
}

func (n *Node) pullRoutes(ctx context.Context) {
	if n.ControllerURL == "" {
		return
	}
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/node-routes/" + url.PathEscape(string(n.ID))
	log.Printf("[config] fetching routes from %s", url)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if tok := n.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[config] pull routes failed: %v", err)
		return
	}
	defer resp.Body.Close()
	var payload routesPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		log.Printf("[config] decode routes failed: %v", err)
		return
	}
	n.updateManualRoutes(buildManualRouteMap(n.ID, payload.Routes))
}

// Prober measures RTT/loss between peers.
type Prober interface {
	Probe(ctx context.Context, local, remote NodeID) (LinkMetrics, error)
}

// WSProber 通过简单的 WebSocket 握手 + Ping 估计 RTT。
type WSProber struct {
	Endpoints  map[NodeID]string
	TLSConfig  *tls.Config
	Timeout    time.Duration
	Transport  string
	ServerName string
}

func (p *WSProber) Probe(ctx context.Context, _, remote NodeID) (LinkMetrics, error) {
	url, ok := p.Endpoints[remote]
	if !ok {
		return LinkMetrics{}, fmt.Errorf("endpoint for %s not found", remote)
	}
	tr := strings.ToLower(p.Transport)
	if strings.HasPrefix(url, "quic://") || tr == "quic" {
		addr := strings.TrimPrefix(url, "quic://")
		if !strings.Contains(addr, ":") {
			return LinkMetrics{}, fmt.Errorf("invalid quic addr %s", addr)
		}
		to := p.Timeout
		if to == 0 {
			to = 8 * time.Second
		}
		ctxDial, cancel := context.WithTimeout(ctx, to)
		defer cancel()
		tlsConf := cloneTLSWithServerName(p.TLSConfig, p.ServerName)
		start := time.Now()
		conn, err := quic.DialAddr(ctxDial, addr, tlsConf, nil)
		if err != nil {
			return LinkMetrics{}, fmt.Errorf("quic probe %s failed: %w", addr, err)
		}
		conn.CloseWithError(0, "probe done")
		return LinkMetrics{
			RTT:       time.Since(start),
			LossRatio: 0,
			UpdatedAt: time.Now(),
		}, nil
	}

	url = normalizeWSEndpoint(probeURL(url))
	to := p.Timeout
	if to == 0 {
		to = 8 * time.Second
	}
	ctxPing, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	start := time.Now()
	var c *websocket.Conn
	var err error
	trOpt := &http.Transport{TLSClientConfig: p.TLSConfig, Proxy: nil}
	dialOpts := &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: trOpt},
	}
	c, _, err = websocket.Dial(ctxPing, url, dialOpts)
	if err != nil && strings.HasPrefix(url, "wss://") {
		wsURL := "ws://" + strings.TrimPrefix(url, "wss://")
		c, _, err = websocket.Dial(ctxPing, wsURL, &websocket.DialOptions{
			HTTPClient: &http.Client{Transport: &http.Transport{Proxy: nil}},
		})
		if err == nil {
			url = wsURL
		}
	}
	if err != nil {
		return LinkMetrics{}, fmt.Errorf("dial probe %s failed: %w", url, err)
	}
	defer c.Close(websocket.StatusNormalClosure, "probe done")
	return LinkMetrics{
		RTT:       time.Since(start),
		LossRatio: 0,
		UpdatedAt: time.Now(),
	}, nil
}

// Transport encapsulates WSS data plane.
type Transport interface {
	Forward(ctx context.Context, src NodeID, path []NodeID, proto Protocol, downstream net.Conn, remoteAddr string) error
	ReconnectTCP(ctx context.Context, src NodeID, proto Protocol, downstream net.Conn, remoteAddr string, computePath func(try int) ([]NodeID, error), attempts int) error
	Serve(ctx context.Context) error
}

// ControlHeader 描述剩余路径和最终出口。
type ControlHeader struct {
	Path        []NodeID `json:"path"`
	RemoteAddr  string   `json:"remote"`
	Proto       Protocol `json:"proto"`
	Compression string   `json:"compress,omitempty"`
	CompressMin int      `json:"compress_min,omitempty"`
}

// UDPDatagram 用于跨 WS 传输单个 UDP 包。
type UDPDatagram struct {
	Src     string `json:"src"`
	Payload []byte `json:"payload"`
}

func probeURL(endpoint string) string {
	if endpoint == "" {
		return endpoint
	}
	if strings.Contains(endpoint, "/probe") {
		return endpoint
	}
	if strings.HasSuffix(endpoint, "/mesh") {
		return strings.TrimSuffix(endpoint, "/mesh") + "/probe"
	}
	return strings.TrimRight(endpoint, "/") + "/probe"
}

func normalizeWSEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	host := u.Host
	if strings.Contains(host, ":") && !strings.Contains(host, "[") {
		h, p, err := net.SplitHostPort(host)
		if err == nil {
			u.Host = fmt.Sprintf("[%s]:%s", h, p)
			return u.String()
		}
		u.Host = fmt.Sprintf("[%s]", host)
		return u.String()
	}
	return endpoint
}

func normalizePeerEndpoint(raw string, mode string) string {
	m := strings.ToLower(mode)
	if strings.HasPrefix(raw, "ws://") || strings.HasPrefix(raw, "wss://") || strings.HasPrefix(raw, "quic://") {
		if m != "quic" && strings.HasPrefix(raw, "ws") && !strings.HasSuffix(raw, "/mesh") {
			return strings.TrimRight(raw, "/") + "/mesh"
		}
		return raw
	}
	// host:port
	if m == "quic" {
		return "quic://" + raw
	}
	if m == "wss" {
		return "wss://" + strings.TrimRight(raw, "/") + "/mesh"
	}
	return "ws://" + strings.TrimRight(raw, "/") + "/mesh"
}

func configDigest(cfg nodeConfig) string {
	b, _ := json.Marshal(cfg)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AckStatus 记录确认链，Confirmed 是已成功下游建立的节点列表（自下而上聚合）。
type AckStatus struct {
	Confirmed []NodeID `json:"confirmed"`
	Note      string   `json:"note,omitempty"`
}

// ControlEnvelope 用于在数据桥接前传递控制信息（首帧 header、ack、错误）。
type ControlEnvelope struct {
	Type      string         `json:"type"` // header | ack | error
	Session   string         `json:"session"`
	Header    *ControlHeader `json:"header,omitempty"`
	Ack       *AckStatus     `json:"ack,omitempty"`
	Error     string         `json:"error,omitempty"`
	Datagram  *UDPDatagram   `json:"datagram,omitempty"` // Type=udp
	Signature string         `json:"sig,omitempty"`
	Version   int            `json:"ver,omitempty"`
	Timestamp int64          `json:"ts,omitempty"` // unix milli
}

// WSSTransport 通过 WebSocket 级联转发，可同时监听 WS 与 WSS。
type WSSTransport struct {
	Self          NodeID
	ListenAddr    string
	TLSListenAddr string
	CertFile      string
	KeyFile       string
	Endpoints     map[NodeID]string // peer -> ws(s)://host:port/mesh
	TLSConfig     *tls.Config
	IdleTimeout   time.Duration
	AuthKey       []byte
	NodeToken     string
	Metrics       *Metrics
	Compression   string
	CompressMin   int
}

func (t *WSSTransport) Forward(ctx context.Context, src NodeID, path []NodeID, proto Protocol, downstream net.Conn, remoteAddr string) error {
	if len(path) < 2 {
		return fmt.Errorf("path too short: %v", path)
	}
	next := path[1]
	targetURL, ok := t.Endpoints[next]
	if !ok {
		return fmt.Errorf("no endpoint for %s", next)
	}
	targetURL = normalizeWSEndpoint(targetURL)
	session := newSessionID()
	header := ControlHeader{
		Path:        path[1:],
		RemoteAddr:  remoteAddr,
		Proto:       proto,
		Compression: t.Compression,
		CompressMin: t.CompressMin,
	}
	ctxDial, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctxDial, targetURL, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: t.TLSConfig}},
	})
	if err != nil {
		downstream.Close()
		return fmt.Errorf("dial next %s failed: %w", next, err)
	}

	if err := writeSignedEnvelope(ctxDial, c, ControlEnvelope{
		Type:    "header",
		Session: session,
		Header:  &header,
	}, t.AuthKey); err != nil {
		downstream.Close()
		return fmt.Errorf("send header failed: %w", err)
	}
	ack, err := readVerifiedEnvelope(ctxDial, c, t.AuthKey)
	if err != nil {
		downstream.Close()
		return fmt.Errorf("await ack failed: %w", err)
	}
	if ack.Type != "ack" {
		downstream.Close()
		return fmt.Errorf("expected ack, got %s: %s", ack.Type, ack.Error)
	}
	log.Printf("[session=%s] 下游 %s 确认链路，已确认: %v", session, next, ack.Ack.Confirmed)
	wsConn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	go func() {
		<-ctx.Done()
		c.Close(websocket.StatusNormalClosure, "ctx canceled")
		wsConn.Close()
	}()
	// 首跳按照请求压缩，后续中间节点在转发时透传
	return bridgeMaybeCompressed(session, downstream, wsConn, header.Compression, header.CompressMin, t.Metrics, path, remoteAddr)
}

// ReconnectTCP 在桥接出错时尝试重新选路重建连接。
func (t *WSSTransport) ReconnectTCP(ctx context.Context, src NodeID, proto Protocol, downstream net.Conn, remoteAddr string, computePath func(try int) ([]NodeID, error), attempts int) error {
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		path, err := computePath(i)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		err = t.Forward(ctx, src, path, proto, downstream, remoteAddr)
		if err == nil {
			return nil
		}
		log.Printf("[reconnect attempt %d/%d] failed: %v", i+1, attempts, err)
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("reconnect attempts exhausted")
}

// OpenUDPSession 建立 UDP 隧道的控制面，返回已握手的 WS 连接与会话 ID。
func (t *WSSTransport) OpenUDPSession(ctx context.Context, path []NodeID, remoteAddr string) (*websocket.Conn, string, error) {
	if len(path) < 2 {
		return nil, "", fmt.Errorf("path too short: %v", path)
	}
	next := path[1]
	targetURL, ok := t.Endpoints[next]
	if !ok {
		return nil, "", fmt.Errorf("no endpoint for %s", next)
	}
	session := newSessionID()
	header := ControlHeader{
		Path:        path[1:],
		RemoteAddr:  remoteAddr,
		Proto:       ProtocolUDP,
		Compression: t.Compression,
		CompressMin: t.CompressMin,
	}
	ctxDial, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctxDial, targetURL, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: t.TLSConfig}},
	})
	if err != nil {
		return nil, "", fmt.Errorf("dial next %s failed: %w", next, err)
	}
	if err := writeSignedEnvelope(ctxDial, c, ControlEnvelope{
		Type:    "header",
		Session: session,
		Header:  &header,
	}, t.AuthKey); err != nil {
		c.Close(websocket.StatusInternalError, "send header failed")
		return nil, "", err
	}
	ack, err := readVerifiedEnvelope(ctxDial, c, t.AuthKey)
	if err != nil {
		c.Close(websocket.StatusInternalError, "await ack failed")
		return nil, "", err
	}
	if ack.Type != "ack" || ack.Ack == nil {
		c.Close(websocket.StatusInternalError, "bad ack")
		return nil, "", fmt.Errorf("expected ack, got %s: %s", ack.Type, ack.Error)
	}
	log.Printf("[session=%s] UDP 下游 %s 确认链路，已确认: %v", session, next, ack.Ack.Confirmed)
	return c, session, nil
}

func (t *WSSTransport) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mesh", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: t.TLSConfig != nil && t.TLSConfig.InsecureSkipVerify,
		})
		if err != nil {
			log.Printf("accept ws failed: %v", err)
			return
		}
		go t.handleConn(ctx, c)
	})
	// Probe endpoint: accept WS and just respond to pings, then close.
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: t.TLSConfig != nil && t.TLSConfig.InsecureSkipVerify,
		})
		if err != nil {
			log.Printf("accept ws probe failed: %v", err)
			return
		}
		go func() {
			defer c.Close(websocket.StatusNormalClosure, "probe done")
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}()
	})

	srv := &http.Server{
		Addr:         t.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	stopServer := func(s *http.Server) {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.Shutdown(shutdownCtx)
	}
	errCh := make(chan error, 2)
	started := 0
	if strings.TrimSpace(t.ListenAddr) != "" {
		started++
		go stopServer(srv)
		go func() {
			log.Printf("WS transport listening on %s", t.ListenAddr)
			errCh <- srv.ListenAndServe()
		}()
	}
	if strings.TrimSpace(t.TLSListenAddr) != "" && t.CertFile != "" && t.KeyFile != "" {
		tlsSrv := &http.Server{
			Addr:         t.TLSListenAddr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			TLSConfig:    t.TLSConfig,
		}
		started++
		go stopServer(tlsSrv)
		go func() {
			log.Printf("WSS transport listening on %s", t.TLSListenAddr)
			errCh <- tlsSrv.ListenAndServeTLS(t.CertFile, t.KeyFile)
		}()
	}
	if started == 0 {
		return fmt.Errorf("no listen address for WS/WSS")
	}
	for i := 0; i < started; i++ {
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}

func (t *WSSTransport) handleConn(ctx context.Context, c *websocket.Conn) {
	defer c.Close(websocket.StatusNormalClosure, "done")
	if t.IdleTimeout > 0 {
		c.SetReadLimit(64 << 20)
	}
	env, err := readVerifiedEnvelope(ctx, c, t.AuthKey)
	if err != nil {
		log.Printf("read header failed: %v", err)
		return
	}
	if env.Type != "header" || env.Header == nil {
		log.Printf("unexpected envelope type %s", env.Type)
		return
	}
	header := *env.Header
	session := env.Session
	if len(header.Path) == 0 {
		log.Printf("empty path in header")
		return
	}
	if header.Path[0] != t.Self {
		log.Printf("path not for me: %v", header.Path)
		return
	}
	remaining := header.Path[1:]

	if len(remaining) == 0 {
		// 当前节点是出口
		switch header.Proto {
		case ProtocolTCP:
			if err := t.handleTCPExit(ctx, session, c, header.RemoteAddr, header.Compression, header.CompressMin); err != nil {
				writeSignedEnvelope(ctx, c, ControlEnvelope{Type: "error", Session: session, Error: err.Error()}, t.AuthKey)
				return
			}
		case ProtocolUDP:
			if err := t.handleUDPExit(ctx, session, c, header.RemoteAddr); err != nil {
				writeSignedEnvelope(ctx, c, ControlEnvelope{Type: "error", Session: session, Error: err.Error()}, t.AuthKey)
				return
			}
		default:
			log.Printf("unknown proto %q", header.Proto)
		}
		return
	}

	// 中间节点：转发到下一跳
	next := remaining[0]
	targetURL, ok := t.Endpoints[next]
	if !ok {
		log.Printf("no endpoint for next hop %s", next)
		return
	}
	ctxDial, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	nextConn, _, err := websocket.Dial(ctxDial, targetURL, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: t.TLSConfig}},
	})
	if err != nil {
		log.Printf("dial next hop %s failed: %v", next, err)
		return
	}
	if err := writeSignedEnvelope(ctxDial, nextConn, ControlEnvelope{
		Type:    "header",
		Session: session,
		Header: &ControlHeader{
			Path:        remaining,
			RemoteAddr:  header.RemoteAddr,
			Proto:       header.Proto,
			Compression: header.Compression,
			CompressMin: header.CompressMin,
		},
	}, t.AuthKey); err != nil {
		log.Printf("forward header failed: %v", err)
		nextConn.Close(websocket.StatusInternalError, "header write failed")
		return
	}
	nextAck, err := readVerifiedEnvelope(ctxDial, nextConn, t.AuthKey)
	if err != nil {
		log.Printf("wait downstream ack failed: %v", err)
		return
	}
	if nextAck.Type != "ack" || nextAck.Ack == nil {
		log.Printf("downstream returned non-ack: %s %s", nextAck.Type, nextAck.Error)
		return
	}
	confirmed := append([]NodeID{t.Self}, nextAck.Ack.Confirmed...)
	if err := writeSignedEnvelope(ctx, c, ControlEnvelope{
		Type:    "ack",
		Session: session,
		Ack:     &AckStatus{Confirmed: confirmed, Note: "forwarded to " + string(next)},
	}, t.AuthKey); err != nil {
		log.Printf("send upstream ack failed: %v", err)
		return
	}

	if header.Proto == ProtocolUDP {
		t.relayUDP(ctx, session, c, nextConn)
		return
	}

	upstream := websocket.NetConn(ctx, c, websocket.MessageBinary)
	downstream := websocket.NetConn(ctx, nextConn, websocket.MessageBinary)
	if err := bridgeWithLogging(session, upstream, downstream, t.Metrics); err != nil {
		log.Printf("[session=%s] bridge failed: %v", session, err)
	}
}

func (t *WSSTransport) handleTCPExit(ctx context.Context, session string, c *websocket.Conn, remoteAddr string, compression string, compressMin int) error {
	out, err := net.DialTimeout("tcp", remoteAddr, 5*time.Second)
	if err != nil {
		log.Printf("[session=%s] dial remote %s failed: %v", session, remoteAddr, err)
		return err
	}
	if err := writeSignedEnvelope(ctx, c, ControlEnvelope{
		Type:    "ack",
		Session: session,
		Ack:     &AckStatus{Confirmed: []NodeID{t.Self}, Note: "exit connected"},
	}, t.AuthKey); err != nil {
		out.Close()
		return fmt.Errorf("send exit ack failed: %w", err)
	}
	conn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	// 出口按照请求的压缩策略处理
	if err := bridgeMaybeCompressed(session, out, conn, compression, compressMin, t.Metrics, nil, remoteAddr); err != nil {
		return err
	}
	return nil
}

func (t *WSSTransport) handleUDPExit(ctx context.Context, session string, c *websocket.Conn, remoteAddr string) error {
	conn, err := net.Dial("udp", remoteAddr)
	if err != nil {
		log.Printf("[session=%s] dial remote udp %s failed: %v", session, remoteAddr, err)
		return err
	}
	if err := writeSignedEnvelope(ctx, c, ControlEnvelope{
		Type:    "ack",
		Session: session,
		Ack:     &AckStatus{Confirmed: []NodeID{t.Self}, Note: "udp exit connected"},
	}, t.AuthKey); err != nil {
		conn.Close()
		return fmt.Errorf("send exit ack failed: %w", err)
	}

	errCh := make(chan error, 2)

	// 下游 -> 远端
	go func() {
		for {
			env, err := readVerifiedEnvelope(ctx, c, t.AuthKey)
			if err != nil {
				errCh <- err
				return
			}
			if env.Type != "udp" || env.Datagram == nil {
				errCh <- fmt.Errorf("unexpected msg type %s", env.Type)
				return
			}
			if _, err := conn.Write(env.Datagram.Payload); err != nil {
				errCh <- err
				return
			}
			if t.Metrics != nil {
				t.Metrics.AddUp(int64(len(env.Datagram.Payload)))
			}
		}
	}()

	// 远端 -> 上游
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			payload := append([]byte(nil), buf[:n]...)
			if err := writeSignedEnvelope(ctx, c, ControlEnvelope{
				Type:     "udp",
				Session:  session,
				Datagram: &UDPDatagram{Src: remoteAddr, Payload: payload},
			}, t.AuthKey); err != nil {
				errCh <- err
				return
			}
			if t.Metrics != nil {
				t.Metrics.AddDown(int64(len(payload)))
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (t *WSSTransport) relayUDP(ctx context.Context, session string, upstream, downstream *websocket.Conn) {
	errCh := make(chan error, 2)
	forward := func(src, dst *websocket.Conn, dir string) {
		for {
			env, err := readVerifiedEnvelope(ctx, src, t.AuthKey)
			if err != nil {
				errCh <- err
				return
			}
			if env.Type != "udp" || env.Datagram == nil {
				errCh <- fmt.Errorf("unexpected msg type %s", env.Type)
				return
			}
			if err := writeSignedEnvelope(ctx, dst, ControlEnvelope{
				Type:     "udp",
				Session:  session,
				Datagram: env.Datagram,
			}, t.AuthKey); err != nil {
				errCh <- err
				return
			}
			if t.Metrics != nil {
				if dir == "down" {
					t.Metrics.AddUp(int64(len(env.Datagram.Payload)))
				} else {
					t.Metrics.AddDown(int64(len(env.Datagram.Payload)))
				}
			}
		}
	}
	go forward(upstream, downstream, "down")
	go forward(downstream, upstream, "up")

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("[session=%s] udp relay error: %v", session, err)
		}
	}
}

func writeSignedEnvelope(ctx context.Context, c *websocket.Conn, env ControlEnvelope, key []byte) error {
	if env.Version == 0 {
		env.Version = 1
	}
	if env.Timestamp == 0 {
		env.Timestamp = time.Now().UnixMilli()
	}
	if len(key) > 0 {
		if err := signEnvelope(&env, key); err != nil {
			return err
		}
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, data)
}

func readVerifiedEnvelope(ctx context.Context, c *websocket.Conn, key []byte) (ControlEnvelope, error) {
	var env ControlEnvelope
	_, data, err := c.Read(ctx)
	if err != nil {
		return env, err
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return env, err
	}
	if env.Version != 1 {
		return env, fmt.Errorf("unsupported version %d", env.Version)
	}
	if env.Timestamp > 0 && time.Since(time.UnixMilli(env.Timestamp)) > 5*time.Minute {
		return env, fmt.Errorf("envelope too old")
	}
	if len(key) == 0 {
		return env, nil
	}
	if err := verifyEnvelope(&env, key); err != nil {
		return env, err
	}
	return env, nil
}

func bridgeWithLogging(session string, a, b net.Conn, m *Metrics) error {
	return bridgeMaybeCompressed(session, a, b, "none", 0, m, nil, "")
}

func bridgeMaybeCompressed(session string, dst, src net.Conn, compression string, minBytes int, m *Metrics, path []NodeID, remote string) error {
	var upCounter, downCounter *int64
	if m != nil {
		upCounter = &m.bytesUp
		downCounter = &m.bytesDown
	}
	compression = strings.ToLower(compression)
	if compression == "" {
		compression = "none"
	}

	pathStr := ""
	if len(path) > 0 {
		parts := make([]string, len(path))
		for i, p := range path {
			parts[i] = string(p)
		}
		pathStr = strings.Join(parts, " -> ")
	}
	log.Printf("[flow session=%s] start bridge compression=%s min=%d from=%s to=%s remote=%s path=%s", session, compression, minBytes, safeAddr(src), safeAddr(dst), remote, pathStr)

	errCh := make(chan error, 2)
	go func() {
		errCh <- copyWithCompression(dst, src, compression, minBytes, downCounter, false)
	}()
	go func() {
		errCh <- copyWithCompression(src, dst, compression, minBytes, upCounter, true)
	}()
	startUp := int64(0)
	startDown := int64(0)
	if m != nil {
		startUp = atomic.LoadInt64(&m.bytesUp)
		startDown = atomic.LoadInt64(&m.bytesDown)
	}
	err1 := <-errCh
	err2 := <-errCh
	dst.Close()
	src.Close()
	err := err1
	if err == nil {
		err = err2
	}
	if err != nil && !isCanceledErr(err) && !errors.Is(err, io.EOF) {
		log.Printf("[session=%s] bridge error: %v", session, err)
	}
	if m != nil {
		up := atomic.LoadInt64(&m.bytesUp) - startUp
		down := atomic.LoadInt64(&m.bytesDown) - startDown
		pathStr := ""
		if len(path) > 0 {
			parts := make([]string, len(path))
			for i, p := range path {
				parts[i] = string(p)
			}
			pathStr = strings.Join(parts, " -> ")
		}
		log.Printf("[flow session=%s] in=%dB out=%dB from=%s to=%s remote=%s path=%s compression=%s", session, down, up, safeAddr(src), safeAddr(dst), remote, pathStr, compression)
	}
	return err
}

func safeAddr(c net.Conn) string {
	if c == nil {
		return ""
	}
	if addr := c.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func dirLabel(compress bool) string {
	if compress {
		return "up/compress"
	}
	return "down/decompress"
}

func logCopyDone(startMsg string, counter *int64, start int64, err error) {
	delta := int64(-1)
	if counter != nil && start >= 0 {
		delta = atomic.LoadInt64(counter) - start
	}
	log.Printf("%s done delta=%d err=%v", startMsg, delta, err)
}

func copyWithCompression(dst net.Conn, src net.Conn, compression string, minBytes int, counter *int64, compress bool) error {
	var startCount int64 = -1
	if counter != nil {
		startCount = atomic.LoadInt64(counter)
	}
	startMsg := fmt.Sprintf("[copy %s] compression=%s src=%s dst=%s", dirLabel(compress), compression, safeAddr(src), safeAddr(dst))
	// none: direct copy
	if compression == "none" {
		n, err := io.Copy(&countingWriter{Writer: dst, counter: counter}, src)
		log.Printf("%s done bytes=%d err=%v", startMsg, n, err)
		return err
	}
	if compression != "gzip" {
		log.Printf("unsupported compression %s, fallback none", compression)
		n, err := io.Copy(&countingWriter{Writer: dst, counter: counter}, src)
		log.Printf("%s (fallback none) done bytes=%d err=%v", startMsg, n, err)
		return err
	}

	if compress {
		err := compressStream(dst, src, compression, minBytes, counter)
		logCopyDone(startMsg, counter, startCount, err)
		return err
	}
	err := decompressStream(dst, src, compression, minBytes, counter)
	logCopyDone(startMsg, counter, startCount, err)
	return err
}

func compressStream(dst net.Conn, src net.Conn, compression string, minBytes int, counter *int64) error {
	log.Printf("[compress] alg=%s min=%d src=%s dst=%s", compression, minBytes, safeAddr(src), safeAddr(dst))
	// Read optional threshold bytes
	if minBytes > 0 {
		buf := make([]byte, minBytes)
		n, err := io.ReadFull(src, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return err
		}
		if n < minBytes && (err == io.ErrUnexpectedEOF || err == io.EOF) {
			// 小流量，直接透传
			if counter != nil {
				atomic.AddInt64(counter, int64(n))
			}
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return werr
				}
			}
			log.Printf("[compress] below threshold (%dB), passthrough", n)
			if err == io.EOF {
				return nil
			}
			return err
		}
		// 达到阈值，开始压缩并写入已读缓冲
		w, closer, err := compressor(dst, compression)
		if err != nil {
			log.Printf("compression %s unavailable, fallback passthrough: %v", compression, err)
			if counter != nil {
				atomic.AddInt64(counter, int64(n))
			}
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return werr
				}
			}
			_, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, src)
			return errCopy
		}
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				closer.Close()
				return werr
			}
			if counter != nil {
				atomic.AddInt64(counter, int64(n))
			}
		}
		_, errCopy := io.Copy(&countingWriter{Writer: w, counter: counter}, src)
		if cerr := closer.Close(); errCopy == nil {
			errCopy = cerr
		}
		return errCopy
	}

	w, closer, err := compressor(dst, compression)
	if err != nil {
		log.Printf("compression %s unavailable, fallback passthrough: %v", compression, err)
		_, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, src)
		return errCopy
	}
	_, err = io.Copy(&countingWriter{Writer: w, counter: counter}, src)
	if cerr := closer.Close(); err == nil {
		err = cerr
	}
	return err
}

func decompressStream(dst net.Conn, src net.Conn, compression string, minBytes int, counter *int64) error {
	log.Printf("[decompress] alg=%s src=%s dst=%s", compression, safeAddr(src), safeAddr(dst))
	br := bufio.NewReader(src)
	peek, err := br.Peek(2)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return err
	}
	if !isCompressedMagic(peek, compression) {
		n, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, br)
		log.Printf("[decompress passthrough] bytes=%d err=%v", n, errCopy)
		return errCopy
	}
	r, closer, derr := decompressor(br, compression)
	if derr != nil {
		// 解压器初始化失败，尝试透传
		log.Printf("[decompress] init failed, passthrough err=%v", derr)
		n, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, br)
		log.Printf("[decompress passthrough] bytes=%d err=%v", n, errCopy)
		return errCopy
	}
	n, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, r)
	if cerr := closer.Close(); errCopy == nil {
		errCopy = cerr
	}
	log.Printf("[decompress done] bytes=%d err=%v", n, errCopy)
	return errCopy
}

type closer interface {
	Close() error
}

// gzipFlushingWriter 在每次 Write 后调用 Flush，避免小包长时间停留在缓冲中。
type gzipFlushingWriter struct {
	zw *gzip.Writer
}

func (g *gzipFlushingWriter) Write(p []byte) (int, error) {
	n, err := g.zw.Write(p)
	// Flush 即便返回错误也要优先返回原始错误
	_ = g.zw.Flush()
	return n, err
}

func compressor(dst io.Writer, alg string) (io.Writer, closer, error) {
	switch alg {
	case "gzip":
		zw := gzip.NewWriter(dst)
		fw := &gzipFlushingWriter{zw: zw}
		return fw, zw, nil
	default:
		return nil, nil, fmt.Errorf("unknown compressor %s", alg)
	}
}

func decompressor(src io.Reader, alg string) (io.Reader, closer, error) {
	switch alg {
	case "gzip":
		r, err := gzip.NewReader(src)
		if err != nil {
			return nil, nil, err
		}
		return r, r, nil
	default:
		return nil, nil, fmt.Errorf("unknown decompressor %s", alg)
	}
}

func isCompressedMagic(peek []byte, alg string) bool {
	if len(peek) < 2 {
		return false
	}
	switch alg {
	case "gzip":
		return peek[0] == 0x1f && peek[1] == 0x8b
	default:
		return false
	}
}

func isCanceledErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return true
	}
	if strings.Contains(err.Error(), "context canceled") {
		return true
	}
	return false
}

type countingWriter struct {
	Writer  io.Writer
	counter *int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	if w.counter != nil {
		atomic.AddInt64(w.counter, int64(len(p)))
	}
	return w.Writer.Write(p)
}

type ManualRoute struct {
	Name     string
	Priority int
	Path     []NodeID
	Remote   string
}

// Node wires entries, probing, routing, and transport.
type Node struct {
	ID             NodeID
	Entries        []EntryPort
	Router         *Router
	Prober         Prober
	Transport      Transport
	Peers          []NodeID
	PollPeriod     time.Duration
	Metrics        *Metrics
	MaxReroute     int
	udpTTL         time.Duration
	ControllerURL  string
	TopologyPull   time.Duration
	RoutePull      time.Duration
	TokenPath      string
	Compression    string
	CompressionMin int
	TransportMode  string
	CertPath       string
	KeyPath        string
	AuthKey        []byte
	DebugLog       bool
	lastMetrics    map[NodeID]LinkMetrics
	metricsMu      sync.Mutex
	routePlans     map[NodeID][]ManualRoute
	routeMu        sync.RWMutex
	tokenOnce      sync.Once
	tokenValue     string
}

func (n *Node) Start(ctx context.Context) error {
	if n.Transport == nil || n.Router == nil || n.Prober == nil {
		return errors.New("node missing Transport/Router/Prober")
	}
	if n.PollPeriod == 0 {
		n.PollPeriod = 3 * time.Second
	}
	if n.ControllerURL != "" {
		if tok := n.loadToken(); tok == "" {
			return fmt.Errorf("controller url set but token missing; please write token to %s or set NODE_TOKEN", n.TokenPath)
		}
	}

	go n.pollMetrics(ctx)
	log.Printf("[topology] controller url: %s", n.ControllerURL)
	if n.ControllerURL != "" {
		go n.pushAndPullLoop(ctx)
		go n.pullRoutesLoop(ctx)
		go n.fetchCertLoop(ctx)
	}
	go func() {
		if err := n.Transport.Serve(ctx); err != nil {
			log.Printf("transport server stopped: %v", err)
		}
	}()
	for _, ep := range n.Entries {
		ep := ep
		switch ep.Proto {
		case ProtocolTCP:
			go n.serveTCP(ctx, ep)
		case ProtocolUDP:
			go n.serveUDP(ctx, ep)
		case Protocol("both"):
			go n.serveTCP(ctx, EntryPort{ListenAddr: ep.ListenAddr, Proto: ProtocolTCP, ExitNode: ep.ExitNode, RemoteAddr: ep.RemoteAddr})
			go n.serveUDP(ctx, EntryPort{ListenAddr: ep.ListenAddr, Proto: ProtocolUDP, ExitNode: ep.ExitNode, RemoteAddr: ep.RemoteAddr})
		default:
			log.Printf("unknown protocol %q on %s", ep.Proto, ep.ListenAddr)
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (n *Node) pollMetrics(ctx context.Context) {
	ticker := time.NewTicker(n.PollPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, peer := range n.Peers {
				metrics, err := n.Prober.Probe(ctx, n.ID, peer)
				if err != nil {
					log.Printf("probe %s -> %s failed: %v", n.ID, peer, err)
					continue
				}
				n.Router.Topology.Set(n.ID, peer, metrics)
				n.recordMetric(peer, metrics)
			}
		}
	}
}

func (n *Node) matchingManualRoutes(exit NodeID, remote string) []ManualRoute {
	n.routeMu.RLock()
	routes := n.routePlans[exit]
	n.routeMu.RUnlock()
	if remote == "" || len(routes) == 0 {
		return routes
	}
	filtered := make([]ManualRoute, 0, len(routes))
	for _, r := range routes {
		if r.Remote == "" || r.Remote == remote {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (n *Node) pathForAttempt(exit NodeID, remote string, attempt int) ([]NodeID, error) {
	routes := n.matchingManualRoutes(exit, remote)
	if attempt < len(routes) {
		r := routes[attempt]
		if len(r.Path) < 2 {
			return nil, fmt.Errorf("manual route %q too short", r.Name)
		}
		if r.Path[0] != n.ID {
			return nil, fmt.Errorf("manual route %q must start from %s", r.Name, n.ID)
		}
		if r.Path[len(r.Path)-1] != exit {
			return nil, fmt.Errorf("manual route %q must end at exit %s", r.Name, exit)
		}
		log.Printf("[route] using manual route %q (priority=%d) for %s -> %s remote=%s: %v", r.Name, r.Priority, n.ID, exit, remote, r.Path)
		return r.Path, nil
	}
	return n.Router.BestPath(n.ID, exit)
}

func (n *Node) routeAttempts(exit NodeID, remote string) int {
	attempts := n.MaxReroute
	routes := n.matchingManualRoutes(exit, remote)
	if attempts < len(routes)+1 {
		attempts = len(routes) + 1
	}
	if attempts < 1 {
		attempts = 1
	}
	return attempts
}

func (n *Node) serveTCP(ctx context.Context, ep EntryPort) {
	ln, err := net.Listen("tcp", ep.ListenAddr)
	if err != nil {
		log.Printf("tcp listen %s failed: %v", ep.ListenAddr, err)
		return
	}
	log.Printf("tcp entry listening on %s -> exit %s (%s)", ep.ListenAddr, ep.ExitNode, ep.RemoteAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept failed on %s: %v", ep.ListenAddr, err)
			continue
		}
		go func(c net.Conn) {
			if n.Metrics != nil {
				n.Metrics.IncTCP()
			}
			attempts := n.routeAttempts(ep.ExitNode, ep.RemoteAddr)
			if err := n.Transport.ReconnectTCP(ctx, n.ID, ep.Proto, c, ep.RemoteAddr, func(try int) ([]NodeID, error) {
				return n.pathForAttempt(ep.ExitNode, ep.RemoteAddr, try)
			}, attempts); err != nil {
				log.Printf("tcp forwarding failed after %d attempts: %v", attempts, err)
				c.Close()
			}
		}(conn)
	}
}

func (n *Node) serveUDP(ctx context.Context, ep EntryPort) {
	transport, ok := n.Transport.(*WSSTransport)
	if !ok {
		log.Printf("udp entry %s requires WSSTransport", ep.ListenAddr)
		return
	}
	pc, err := net.ListenPacket("udp", ep.ListenAddr)
	if err != nil {
		log.Printf("udp listen %s failed: %v", ep.ListenAddr, err)
		return
	}
	log.Printf("udp entry listening on %s -> exit %s (%s)", ep.ListenAddr, ep.ExitNode, ep.RemoteAddr)
	sessions := make(map[string]*udpSession)
	var mu sync.Mutex
	ttl := n.udpTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	buf := make([]byte, 64*1024)
	for {
		nBytes, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("udp read failed: %v", err)
			continue
		}
		data := append([]byte(nil), buf[:nBytes]...)
		go func(pkt []byte, clientAddr net.Addr) {
			key := clientAddr.String()
			mu.Lock()
			sess := sessions[key]
			if sess == nil {
				attempts := n.routeAttempts(ep.ExitNode, ep.RemoteAddr)
				var path []NodeID
				var sessionID string
				var wsConn *websocket.Conn
				var err error
				for try := 0; try < attempts; try++ {
					path, err = n.pathForAttempt(ep.ExitNode, ep.RemoteAddr, try)
					if err != nil {
						log.Printf("udp route selection failed (attempt %d/%d): %v", try+1, attempts, err)
						continue
					}
					wsConn, sessionID, err = transport.OpenUDPSession(ctx, path, ep.RemoteAddr)
					if err == nil {
						break
					}
					log.Printf("open udp session failed via route %d/%d: %v", try+1, attempts, err)
				}
				if err != nil {
					mu.Unlock()
					log.Printf("open udp session failed after %d attempts: %v", attempts, err)
					return
				}
				if n.Metrics != nil {
					n.Metrics.IncUDP()
				}
				sessCtx, cancel := context.WithCancel(ctx)
				sess = &udpSession{conn: wsConn, cancel: cancel, clientAddr: clientAddr, sessionID: sessionID}
				sessions[key] = sess
				go n.udpDownstreamLoop(sessCtx, pc, sess, transport.AuthKey, n.Metrics, func() {
					mu.Lock()
					delete(sessions, key)
					mu.Unlock()
				})
			}
			mu.Unlock()
			if sess == nil {
				return
			}
			if err := writeSignedEnvelope(ctx, sess.conn, ControlEnvelope{
				Type:     "udp",
				Session:  sess.sessionID,
				Datagram: &UDPDatagram{Src: clientAddr.String(), Payload: pkt},
			}, transport.AuthKey); err != nil {
				log.Printf("send udp datagram failed: %v", err)
				sess.cancel()
				mu.Lock()
				delete(sessions, key)
				mu.Unlock()
				return
			}
			if n.Metrics != nil {
				n.Metrics.AddUp(int64(len(pkt)))
			}
			// 更新最后活跃时间
			sess.touch()
		}(data, addr)

		// 定期清理过期 UDP 会话
		mu.Lock()
		now := time.Now()
		for k, s := range sessions {
			last := time.UnixMilli(s.lastActive.Load())
			if now.Sub(last) > ttl {
				s.cancel()
				delete(sessions, k)
			}
		}
		mu.Unlock()
	}
}

type udpSession struct {
	conn       *websocket.Conn
	cancel     context.CancelFunc
	clientAddr net.Addr
	sessionID  string
	lastActive atomic.Int64
}

func (n *Node) udpDownstreamLoop(ctx context.Context, pc net.PacketConn, sess *udpSession, key []byte, metrics *Metrics, cleanup func()) {
	defer func() {
		if sess.conn != nil {
			sess.conn.Close(websocket.StatusNormalClosure, "udp session closed")
		}
		cleanup()
	}()
	for {
		env, err := readVerifiedEnvelope(ctx, sess.conn, key)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				log.Printf("[session=%s] udp downstream err: %v", sess.sessionID, err)
			}
			return
		}
		if env.Type != "udp" || env.Datagram == nil {
			log.Printf("[session=%s] unexpected msg type %s", sess.sessionID, env.Type)
			continue
		}
		if _, err := pc.WriteTo(env.Datagram.Payload, sess.clientAddr); err != nil {
			log.Printf("[session=%s] udp write back failed: %v", sess.sessionID, err)
			return
		}
		if metrics != nil {
			metrics.AddDown(int64(len(env.Datagram.Payload)))
		}
		sess.touch()
	}
}

func (s *udpSession) touch() {
	s.lastActive.Store(time.Now().UnixMilli())
}

type entryConfig struct {
	Listen string `json:"listen"`
	Proto  string `json:"proto"`
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
}

type routePlanConfig struct {
	Name     string   `json:"name"`
	Exit     string   `json:"exit"`
	Remote   string   `json:"remote"`
	Priority int      `json:"priority"`
	Path     []string `json:"path"`
}

type nodeConfig struct {
	ID              string            `json:"id"`
	WSListen        string            `json:"ws_listen"`
	QUICListen      string            `json:"quic_listen"`
	WSSListen       string            `json:"wss_listen"`
	Peers           map[string]string `json:"peers"` // node -> ws(s)://host:port/mesh
	Entries         []entryConfig     `json:"entries"`
	Routes          []routePlanConfig `json:"routes"`
	PollPeriod      string            `json:"poll_period"`
	InsecureSkipTLS bool              `json:"insecure_skip_tls"`
	QUICServerName  string            `json:"quic_server_name"`
	MaxIdle         string            `json:"quic_max_idle"`
	MaxDatagramSize int               `json:"quic_max_datagram_size"`
	AuthKey         string            `json:"auth_key"`
	MetricsListen   string            `json:"metrics_listen"`
	RerouteAttempts int               `json:"reroute_attempts"`
	UDPSessionTTL   string            `json:"udp_session_ttl"`
	MTLSCert        string            `json:"mtls_cert"`
	MTLSKey         string            `json:"mtls_key"`
	MTLSCA          string            `json:"mtls_ca"`
	ControllerURL   string            `json:"controller_url"`
	TopologyPull    string            `json:"topology_pull"`
	RoutePull       string            `json:"route_pull"`
	Compression     string            `json:"compression"`
	CompressionMin  int               `json:"compression_min_bytes"`
	Transport       string            `json:"transport"`
	TokenPath       string            `json:"token_path"`
	DebugLog        bool              `json:"debug_log"`
}

func loadConfig(path string) (nodeConfig, error) {
	var cfg nodeConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	fmt.Println("Config data:", string(data))
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.ID == "" {
		return cfg, errors.New("id required")
	}
	if cfg.WSListen == "" && cfg.WSSListen == "" {
		return cfg, errors.New("at least one of ws_listen or wss_listen required")
	}
	if cfg.ControllerURL != "" {
		cfg.ControllerURL = strings.TrimRight(cfg.ControllerURL, "/")
	}
	if cfg.Transport == "" {
		cfg.Transport = "quic"
	}
	// 默认证书/密钥路径并按平台重写
	if cfg.MTLSCert == "" {
		cfg.MTLSCert = "/opt/arouter/certs/arouter.crt"
	}
	if cfg.MTLSKey == "" {
		cfg.MTLSKey = "/opt/arouter/certs/arouter.key"
	}
	if cfg.MTLSCA == "" {
		cfg.MTLSCA = "/opt/arouter/certs/arouter.crt"
	}
	cfg.MTLSCert = platformPath(cfg.MTLSCert)
	cfg.MTLSKey = platformPath(cfg.MTLSKey)
	cfg.MTLSCA = platformPath(cfg.MTLSCA)
	if cfg.TokenPath != "" {
		cfg.TokenPath = platformPath(cfg.TokenPath)
	}
	return cfg, nil
}

func (n *nodeConfig) fetchCert() {
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/certs"
	log.Printf("[config] fetching cert from %s", url)
	token, err := os.ReadFile(n.TokenPath)
	if err != nil {
		log.Fatalf("[config] failed to read token: %v", err)
	}
	tok := strings.TrimSpace(string(token))
	fmt.Println("Authorization token", tok)
	header := &http.Header{}
	header.Set("Authorization", "Bearer "+tok)
	resp := http2.GETWithHeader(url, nil, header)
	if resp.Error() != nil {
		log.Printf("[config] fetch cert failed: %v", resp.Error())
		return
	}
	if resp.StatusCode >= 300 {
		log.Printf("[config] fetch cert non-2xx: %s body=%s", resp.StatusCode, string(resp.Byte()))
		return
	}
	var payload certPayload

	if err := resp.Resp(&payload); err != nil {
		log.Printf("[config] decode cert payload failed: %v", err)
		return
	}
	if payload.Cert == "" || payload.Key == "" {
		log.Printf("[config] cert payload empty")
		return
	}
	ensureDir := func(path string) error {
		dir := filepath.Dir(path)
		if dir == "" || dir == "." {
			return nil
		}
		return os.MkdirAll(dir, 0700)
	}
	if err := ensureDir(n.MTLSCert); err != nil {
		log.Printf("[config] ensure cert dir failed: %v", err)
		return
	}
	if err := ensureDir(n.MTLSKey); err != nil {
		log.Printf("[config] ensure key dir failed: %v", err)
		return
	}
	if err := os.WriteFile(n.MTLSCert, []byte(payload.Cert), 0600); err != nil {
		log.Printf("[config] write cert failed: %v", err)
		return
	}
	if err := os.WriteFile(n.MTLSKey, []byte(payload.Key), 0600); err != nil {
		log.Printf("[config] write key failed: %v", err)
		return
	}
	log.Printf("[config] updated cert/key from controller -> cert=%s key=%s", n.MTLSCert, n.MTLSKey)
}
func parseDurationOrDefault(raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return def
	}
	return d
}

func buildManualRouteMap(self NodeID, routes []routePlanConfig) map[NodeID][]ManualRoute {
	plans := make(map[NodeID][]ManualRoute)
	for _, r := range routes {
		if len(r.Path) == 0 {
			continue
		}
		path := make([]NodeID, 0, len(r.Path))
		for _, p := range r.Path {
			path = append(path, NodeID(p))
		}
		if path[0] != self {
			path = append([]NodeID{self}, path...)
		}
		exit := path[len(path)-1]
		plans[exit] = append(plans[exit], ManualRoute{
			Name:     r.Name,
			Priority: r.Priority,
			Path:     path,
			Remote:   r.Remote,
		})
	}
	for exit := range plans {
		sort.Slice(plans[exit], func(i, j int) bool {
			if plans[exit][i].Priority == plans[exit][j].Priority {
				return plans[exit][i].Name < plans[exit][j].Name
			}
			return plans[exit][i].Priority < plans[exit][j].Priority
		})
	}
	return plans
}

func (n *Node) updateManualRoutes(plans map[NodeID][]ManualRoute) {
	n.routeMu.Lock()
	n.routePlans = plans
	n.routeMu.Unlock()
}

func platformPath(p string) string {
	// expand ~ and ${HOME}
	if strings.HasPrefix(p, "~") {
		home, _ := os.UserHomeDir()
		if home != "" {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	if strings.HasPrefix(p, "${HOME}") {
		home, _ := os.UserHomeDir()
		if home != "" {
			p = filepath.Join(home, strings.TrimPrefix(p, "${HOME}"))
		}
	}
	if runtime.GOOS == "darwin" && strings.HasPrefix(p, "/opt/arouter") {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			return filepath.Join(home, ".arouter"+strings.TrimPrefix(p, "/opt/arouter"))
		}
	}
	return p
}

// loadToken 读取节点 token，优先环境变量 NODE_TOKEN，其次文件 TokenPath/.token。
func (n *Node) loadToken() string {
	n.tokenOnce.Do(func() {
		if tok := os.Getenv("NODE_TOKEN"); tok != "" {
			n.tokenValue = tok
			return
		}
		path := n.TokenPath
		if strings.TrimSpace(path) == "" {
			path = "/opt/arouter/.token"
		}
		data, err := os.ReadFile(path)
		if err == nil {
			n.tokenValue = strings.TrimSpace(string(data))
		} else {
			log.Printf("token file read failed (%s): %v", path, err)
		}
	})
	return n.tokenValue
}

func buildTLSConfig(cfg nodeConfig) (*tls.Config, error) {
	if cfg.MTLSCert == "" && cfg.MTLSKey == "" && cfg.MTLSCA == "" {
		return &tls.Config{InsecureSkipVerify: cfg.InsecureSkipTLS}, nil
	}
	if cfg.MTLSCert == "" || cfg.MTLSKey == "" {
		return nil, fmt.Errorf("mtls_cert and mtls_key required when mtls_ca provided")
	}
	certPath := platformPath(cfg.MTLSCert)
	keyPath := platformPath(cfg.MTLSKey)
	caPath := platformPath(cfg.MTLSCA)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: cfg.InsecureSkipTLS,
	}
	if cfg.MTLSCA != "" {
		caData, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to load mtls_ca")
		}
		tlsConf.ClientCAs = pool
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConf.RootCAs = pool
	} else {
		// 无 CA 时，将自签名证书本身加入 RootCAs 以便信任自签。
		pool := x509.NewCertPool()
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(certPEM) {
			return nil, fmt.Errorf("failed to append self-signed cert to root pool")
		}
		tlsConf.RootCAs = pool
		// 提取叶子用于 ClientAuth 验证。
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("invalid pem in self-signed cert")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			tlsConf.ClientCAs = pool
			tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConf.ServerName = cert.Subject.CommonName
		}
	}
	return tlsConf, nil
}

func cloneTLSWithServerName(base *tls.Config, serverName string) *tls.Config {
	var tlsConf *tls.Config
	if base != nil {
		tlsConf = base.Clone()
	} else {
		tlsConf = &tls.Config{}
	}
	tlsConf.InsecureSkipVerify = true
	tlsConf.ServerName = ""
	if strings.TrimSpace(serverName) != "" {
		tlsConf.ServerName = serverName
		tlsConf.InsecureSkipVerify = false
	}
	return tlsConf
}

func main() {
	configPath := flag.String("config", "config.json", "path to JSON config")
	tokenPath := flag.String("token", "/opt/arouter/.token", "path to node token file")
	flag.Parse()

	log.Printf("arouter agent version %s", buildVersion)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGUSR1)

	var lastCfgDigest string

	for {
		cfg, err := loadConfig(*configPath)
		if err != nil {
			log.Fatalf("load config failed: %v", err)
		}
		cfgDigest := configDigest(cfg)
		if cfgDigest == lastCfgDigest {
			log.Printf("config unchanged, skip reload")
			select {
			case <-sigCh:
				continue
			case <-time.After(5 * time.Second):
				continue
			}
		}
		lastCfgDigest = cfgDigest
		metrics := &Metrics{}
		var metricsSrv *http.Server
		if cfg.MetricsListen != "" {
			metricsSrv = metrics.Serve(cfg.MetricsListen)
			log.Printf("metrics listening on %s", cfg.MetricsListen)
		}
		topology := NewTopology()
		router := &Router{Topology: topology}

		{
			//构建之前要先拉取certs
			_, errStat := os.Stat(cfg.MTLSCert)
			if errStat != nil {
				fmt.Println("不存在cert文件，尝试从controller拉取")
				cfg.fetchCert()
				fmt.Println("拉取cert文件完成")
			}
		}

		fmt.Println("构建节点...")
		tlsConf, err := buildTLSConfig(cfg)
		if err != nil {
			log.Fatalf("build tls config failed: %v", err)
		}
		authKey := []byte(cfg.AuthKey)
		endpoints := make(map[NodeID]string, len(cfg.Peers))
		peerIDs := make([]NodeID, 0, len(cfg.Peers))
		defaultPort := func(listen string, fallback string) string {
			l := strings.TrimSpace(listen)
			if strings.HasPrefix(l, ":") {
				return strings.TrimPrefix(l, ":")
			}
			if strings.Contains(l, ":") {
				parts := strings.Split(l, ":")
				return parts[len(parts)-1]
			}
			if l != "" {
				return l
			}
			return fallback
		}
		mode := strings.ToLower(cfg.Transport)
		if mode == "" {
			mode = "quic"
		}
		port := defaultPort(cfg.QUICListen, defaultPort(cfg.WSSListen, defaultPort(cfg.WSListen, "18080")))
		for id, addr := range cfg.Peers {
			raw := strings.TrimSpace(addr)
			if strings.Contains(raw, "://") {
				endpoints[NodeID(id)] = normalizePeerEndpoint(raw, mode)
			} else {
				host := raw
				if !strings.Contains(host, ":") {
					host = net.JoinHostPort(host, port)
				}
				if strings.Contains(host, ":") && !strings.Contains(host, "[") {
					h, p, err := net.SplitHostPort(host)
					if err == nil {
						host = net.JoinHostPort(h, p)
					}
				}
				endpoints[NodeID(id)] = normalizePeerEndpoint(host, mode)
			}
			peerIDs = append(peerIDs, NodeID(id))
		}

		entries := make([]EntryPort, 0, len(cfg.Entries))
		for _, e := range cfg.Entries {
			entries = append(entries, EntryPort{
				ListenAddr: e.Listen,
				Proto:      Protocol(e.Proto),
				ExitNode:   NodeID(e.Exit),
				RemoteAddr: e.Remote,
			})
		}

		udpTTL := parseDurationOrDefault(cfg.UDPSessionTTL, 60*time.Second)
		routePull := parseDurationOrDefault(cfg.RoutePull, 0)
		compression := strings.ToLower(cfg.Compression)
		if compression == "" {
			compression = "gzip"
		}
		var transport Transport
		switch mode {
		case "quic":
			transport = &QUICTransport{
				Self:            NodeID(cfg.ID),
				ListenAddr:      defaultIfEmpty(cfg.QUICListen, cfg.WSListen),
				Endpoints:       endpoints,
				TLSConfig:       tlsConf,
				ServerName:      cfg.QUICServerName,
				MaxIdleTimeout:  parseDurationOrDefault(cfg.MaxIdle, 0),
				MaxDatagramSize: cfg.MaxDatagramSize,
				AuthKey:         authKey,
				Metrics:         metrics,
				Compression:     compression,
				CompressMin:     cfg.CompressionMin,
			}
		case "wss", "ws":
			transport = &WSSTransport{
				Self:          NodeID(cfg.ID),
				ListenAddr:    cfg.WSListen,
				TLSListenAddr: cfg.WSSListen,
				CertFile:      platformPath(defaultIfEmpty(cfg.MTLSCert, "/opt/arouter/certs/arouter.crt")),
				KeyFile:       platformPath(defaultIfEmpty(cfg.MTLSKey, "/opt/arouter/certs/arouter.key")),
				Endpoints:     endpoints,
				TLSConfig:     tlsConf,
				AuthKey:       authKey,
				Metrics:       metrics,
				Compression:   compression,
				CompressMin:   cfg.CompressionMin,
			}
		default:
			log.Printf("unknown transport %s, fallback to ws", mode)
			transport = &WSSTransport{
				Self:          NodeID(cfg.ID),
				ListenAddr:    cfg.WSListen,
				TLSListenAddr: cfg.WSSListen,
				CertFile:      platformPath(defaultIfEmpty(cfg.MTLSCert, "/opt/arouter/certs/arouter.crt")),
				KeyFile:       platformPath(defaultIfEmpty(cfg.MTLSKey, "/opt/arouter/certs/arouter.key")),
				Endpoints:     endpoints,
				TLSConfig:     tlsConf,
				AuthKey:       authKey,
				Metrics:       metrics,
				Compression:   compression,
				CompressMin:   cfg.CompressionMin,
			}
		}
		prober := &WSProber{
			Endpoints:  endpoints,
			TLSConfig:  tlsConf,
			Transport:  mode,
			ServerName: cfg.QUICServerName,
		}

		routePlans := buildManualRouteMap(NodeID(cfg.ID), cfg.Routes)

		node := &Node{
			ID:             NodeID(cfg.ID),
			Entries:        entries,
			Router:         router,
			Prober:         prober,
			Transport:      transport,
			Peers:          peerIDs,
			PollPeriod:     parseDurationOrDefault(cfg.PollPeriod, 5*time.Second),
			Metrics:        metrics,
			MaxReroute:     cfg.RerouteAttempts,
			udpTTL:         udpTTL,
			ControllerURL:  cfg.ControllerURL,
			TopologyPull:   parseDurationOrDefault(cfg.TopologyPull, 5*time.Minute),
			RoutePull:      routePull,
			Compression:    compression,
			CompressionMin: cfg.CompressionMin,
			TransportMode:  mode,
			CertPath:       platformPath(defaultIfEmpty(cfg.MTLSCert, "/opt/arouter/certs/arouter.crt")),
			KeyPath:        platformPath(defaultIfEmpty(cfg.MTLSKey, "/opt/arouter/certs/arouter.key")),
			AuthKey:        authKey,
			routePlans:     routePlans,
			TokenPath:      platformPath(defaultIfEmpty(*tokenPath, "/opt/arouter/.token")),
			DebugLog:       cfg.DebugLog,
		}

		ctx, cancel := context.WithCancel(context.Background())
		nodeDone := make(chan struct{})
		go func() {
			defer close(nodeDone)
			log.Printf("starting node %s", node.ID)
			if err := node.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("node stopped: %v", err)
			}
		}()
		if metricsSrv != nil {
			go func() {
				<-ctx.Done()
				shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
				defer c()
				metricsSrv.Shutdown(shutdownCtx)
			}()
		}

		select {
		case <-sigCh:
			log.Printf("received reload signal, reloading config")
			cancel()
			<-nodeDone
			continue
		case <-nodeDone:
			return
		}
	}
}

func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func signEnvelope(env *ControlEnvelope, key []byte) error {
	sig := env.Signature
	env.Signature = ""
	origTS := env.Timestamp
	if origTS == 0 {
		env.Timestamp = time.Now().UnixMilli()
	}
	data, err := json.Marshal(env)
	if err != nil {
		env.Signature = sig
		env.Timestamp = origTS
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	env.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

func verifyEnvelope(env *ControlEnvelope, key []byte) error {
	expected := env.Signature
	env.Signature = ""
	if env.Timestamp == 0 {
		return fmt.Errorf("missing timestamp")
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	raw, err := hex.DecodeString(expected)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	if !hmac.Equal(raw, mac.Sum(nil)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
