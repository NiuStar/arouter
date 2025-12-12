package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql/driver"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var buildVersion = "dev"
var jwtSecret []byte

//go:embed certs/arouter.crt
var defaultCert []byte

//go:embed certs/arouter.key
var defaultKey []byte

//go:embed config_pull.sh.tmpl
var configPullTemplate string

type Node struct {
	ID              uint        `gorm:"primaryKey" json:"id"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
	Name            string      `gorm:"uniqueIndex" json:"name"`
	WSListen        string      `json:"ws_listen"`
	MetricsListen   string      `json:"metrics_listen"`
	AuthKey         string      `json:"auth_key"`
	InsecureSkipTLS bool        `json:"insecure_skip_tls"`
	QUICServerName  string      `json:"quic_server_name"`
	RerouteAttempts int         `json:"reroute_attempts"`
	UDPSessionTTL   string      `json:"udp_session_ttl"`
	PollPeriod      string      `json:"poll_period"`
	MTLSCert        string      `json:"mtls_cert"`
	MTLSKey         string      `json:"mtls_key"`
	MTLSCA          string      `json:"mtls_ca"`
	ControllerURL   string      `json:"controller_url"`
	Compression     string      `json:"compression"`
	CompressionMin  int         `json:"compression_min_bytes"`
	Transport       string      `json:"transport"`
	QUICListen      string      `json:"quic_listen"`
	WSSListen       string      `json:"wss_listen"`
	Entries         []Entry     `json:"entries"`
	Peers           []Peer      `json:"peers"`
	Routes          []RoutePlan `json:"routes"`
	LastCPU         float64     `json:"cpu_usage"`
	MemUsed         uint64      `json:"mem_used_bytes"`
	MemTotal        uint64      `json:"mem_total_bytes"`
	UptimeSec       uint64      `json:"uptime_sec"`
	NetInBytes      uint64      `json:"net_in_bytes"`
	NetOutBytes     uint64      `json:"net_out_bytes"`
	NodeVersion     string      `json:"node_version"`
	LastSeenAt      time.Time   `json:"last_seen_at"`
	Token           string      `json:"token"`
	OSName          string      `json:"os_name"`
	Arch            string      `json:"arch"`
	PublicIPs       StringList  `json:"public_ips"`
}

type LinkMetric struct {
	From      string    `gorm:"primaryKey;column:from_node" json:"from"`
	To        string    `gorm:"primaryKey;column:to_node" json:"to"`
	RTTMs     int64     `json:"rtt_ms"`
	Loss      float64   `json:"loss"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LinkMetricsJSON struct {
	RTTms     int64     `json:"rtt_ms"`
	Loss      float64   `json:"loss"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Entry struct {
	ID     uint   `gorm:"primaryKey" json:"id"`
	NodeID uint   `json:"-"`
	Listen string `json:"listen"`
	Proto  string `json:"proto"` // tcp/udp/both
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
}

type StringList []string

func (s StringList) Value() (driver.Value, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *StringList) Scan(value interface{}) error {
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return fmt.Errorf("unsupported type %T", value)
	}
}

type RoutePlan struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	NodeID    uint       `json:"-"`
	Name      string     `json:"name"`
	Exit      string     `json:"exit"`
	Remote    string     `json:"remote"`
	Priority  int        `json:"priority"`
	Path      StringList `json:"path"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type Peer struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	NodeID   uint   `json:"-"`
	PeerName string `json:"peer_name"`
	Endpoint string `json:"endpoint"` // ws(s)://host:port/mesh
	EntryIP  string `json:"entry_ip"` // 对端入口 IP
	ExitIP   string `json:"exit_ip"`  // 本节点出口 IP
}

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Username     string    `gorm:"uniqueIndex" json:"username"`
	PasswordHash string    `json:"-"`
	IsAdmin      bool      `json:"is_admin"`
}

// Setting 为全局系统设置，影响所有节点。
type Setting struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	Transport      string `json:"transport"`
	Compression    string `json:"compression"`
	CompressionMin int    `json:"compression_min_bytes"`
	DebugLog       bool   `json:"debug_log"`
	HTTPProbeURL   string `json:"http_probe_url"`
}

type RouteProbe struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Node      string     `gorm:"uniqueIndex:idx_node_route" json:"node"`
	Route     string     `gorm:"uniqueIndex:idx_node_route" json:"route"`
	Path      StringList `json:"path"`
	RTTMs     int64      `json:"rtt_ms"`
	Success   bool       `json:"success"`
	Error     string     `json:"error"`
}

type UserClaims struct {
	UserID  uint `json:"uid"`
	IsAdmin bool `json:"is_admin"`
}

type ConfigResponse struct {
	ID              string            `json:"id"`
	WSListen        string            `json:"ws_listen"`
	QUICListen      string            `json:"quic_listen"`
	WSSListen       string            `json:"wss_listen"`
	QUICServerName  string            `json:"quic_server_name"`
	Peers           map[string]string `json:"peers"`
	Entries         []EntryConfig     `json:"entries"`
	PollPeriod      string            `json:"poll_period"`
	InsecureSkipTLS bool              `json:"insecure_skip_tls"`
	AuthKey         string            `json:"auth_key"`
	MetricsListen   string            `json:"metrics_listen"`
	RerouteAttempts int               `json:"reroute_attempts"`
	UDPSessionTTL   string            `json:"udp_session_ttl"`
	MTLSCert        string            `json:"mtls_cert"`
	MTLSKey         string            `json:"mtls_key"`
	MTLSCA          string            `json:"mtls_ca"`
	ControllerURL   string            `json:"controller_url"`
	Routes          []RouteConfig     `json:"routes,omitempty"`
	Compression     string            `json:"compression,omitempty"`
	CompressionMin  int               `json:"compression_min_bytes,omitempty"`
	Transport       string            `json:"transport,omitempty"`
	DebugLog        bool              `json:"debug_log,omitempty"`
	TokenPath       string            `json:"token_path,omitempty"`
	OS              string            `json:"os,omitempty"`
	Arch            string            `json:"arch,omitempty"`
	HTTPProbeURL    string            `json:"http_probe_url,omitempty"`
}

// applyOSOverrides 根据 os hint（例如 darwin）调整默认路径，便于节点在不同平台使用合适的目录。
func applyOSOverrides(cfg ConfigResponse, osHint string) ConfigResponse {
	if osHint == "darwin" {
		if strings.HasPrefix(cfg.MTLSCert, "/opt/arouter/") {
			cfg.MTLSCert = strings.Replace(cfg.MTLSCert, "/opt/arouter", "${HOME}/.arouter", 1)
		}
		if strings.HasPrefix(cfg.MTLSKey, "/opt/arouter/") {
			cfg.MTLSKey = strings.Replace(cfg.MTLSKey, "/opt/arouter", "${HOME}/.arouter", 1)
		}
		if strings.HasPrefix(cfg.MTLSCA, "/opt/arouter/") {
			cfg.MTLSCA = strings.Replace(cfg.MTLSCA, "/opt/arouter", "${HOME}/.arouter", 1)
		}
		if cfg.TokenPath == "" || strings.HasPrefix(cfg.TokenPath, "/opt/arouter/") {
			cfg.TokenPath = strings.Replace("/opt/arouter/.token", "/opt/arouter", "${HOME}/.arouter", 1)
		}
	}
	return cfg
}

func applyInstallDirOverrides(cfg ConfigResponse, installDir string) ConfigResponse {
	if installDir == "" {
		return cfg
	}
	replacePath := func(v string) string {
		if v == "" {
			return v
		}
		if strings.Contains(v, "${HOME}") {
			return strings.ReplaceAll(v, "${HOME}", installDir)
		}
		if strings.HasPrefix(v, "/opt/arouter") {
			return strings.Replace(v, "/opt/arouter", installDir, 1)
		}
		return v
	}
	cfg.MTLSCert = replacePath(cfg.MTLSCert)
	cfg.MTLSKey = replacePath(cfg.MTLSKey)
	cfg.MTLSCA = replacePath(cfg.MTLSCA)
	cfg.TokenPath = replacePath(cfg.TokenPath)
	return cfg
}

type RouteConfig struct {
	Name     string   `json:"name"`
	Exit     string   `json:"exit"`
	Remote   string   `json:"remote,omitempty"`
	Priority int      `json:"priority"`
	Path     []string `json:"path"`
}

type EntryConfig struct {
	Listen string `json:"listen"`
	Proto  string `json:"proto"`
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
}

func main() {
	db := mustOpenDB()
	auth := NewGlobalAuth(envOrDefault("AUTH_KEY_FILE", "/app/data/auth.key"))
	globalKey := auth.LoadOrCreate()
	if err := db.AutoMigrate(&Node{}, &Entry{}, &Peer{}, &LinkMetric{}, &RoutePlan{}, &Setting{}, &User{}, &RouteProbe{}); err != nil {
		log.Fatalf("migrate failed: %v", err)
	}
	ensureColumns(db)
	ensureGlobalSettings(db)
	jwtSecret = []byte(envOrDefault("JWT_SECRET", randomKey()))
	log.Printf("arouter controller version %s", buildVersion)

	r := gin.Default()

	distDir := envOrDefault("WEB_DIST", "web/dist")
	if info, err := os.Stat(distDir); err == nil && info.IsDir() {
		log.Printf("serving static front-end from %s", distDir)
		assetsDir := filepath.Join(distDir, "assets")
		if _, err := os.Stat(assetsDir); err == nil {
			r.Static("/assets", assetsDir)
		}
		r.StaticFile("/favicon.ico", filepath.Join(distDir, "favicon.ico"))
		r.GET("/", func(c *gin.Context) {
			c.File(filepath.Join(distDir, "index.html"))
		})
		r.NoRoute(func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			// try to serve existing file
			path := filepath.Clean(c.Request.URL.Path)
			fpath := filepath.Join(distDir, path)
			if info, err := os.Stat(fpath); err == nil && !info.IsDir() {
				c.File(fpath)
				return
			}
			// fallback to SPA entry
			c.File(filepath.Join(distDir, "index.html"))
		})
	} else {
		log.Printf("static front-end not found (%s), please build React front-end into this path", distDir)
		r.GET("/", func(c *gin.Context) {
			c.String(http.StatusOK, "Front-end not found. Build React app and set WEB_DIST to its dist directory.")
		})
	}

	api := r.Group("/api")
	authGroup := api.Group("")
	authGroup.Use(authUserMiddleware(db))
	authGroup.GET("/me", func(c *gin.Context) {
		u, _ := c.Get("user")
		c.JSON(http.StatusOK, u)
	})
	authGroup.GET("/users", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		var users []User
		db.Find(&users)
		c.JSON(http.StatusOK, users)
	})
	authGroup.POST("/users", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			IsAdmin  bool   `json:"is_admin"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		if req.Username == "" || req.Password == "" {
			c.String(http.StatusBadRequest, "username/password required")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		user := User{Username: req.Username, PasswordHash: string(hash), IsAdmin: req.IsAdmin}
		if err := db.Create(&user).Error; err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusCreated, user)
	})
	authGroup.PUT("/users/:id", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		id := c.Param("id")
		var req struct {
			Password string `json:"password"`
			IsAdmin  *bool  `json:"is_admin"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		updates := map[string]interface{}{}
		if req.Password != "" {
			hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			updates["password_hash"] = string(hash)
		}
		if req.IsAdmin != nil {
			updates["is_admin"] = *req.IsAdmin
		}
		if len(updates) == 0 {
			c.String(http.StatusBadRequest, "nothing to update")
			return
		}
		if err := db.Model(&User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.Status(http.StatusNoContent)
	})
	authGroup.DELETE("/users/:id", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		id := c.Param("id")
		if err := db.Delete(&User{}, "id = ?", id).Error; err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.Status(http.StatusNoContent)
	})
	// login
	api.POST("/login", func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		var cnt int64
		db.Model(&User{}).Count(&cnt)
		if cnt == 0 {
			// 首个用户自动创建为管理员
			hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			user := User{Username: req.Username, PasswordHash: string(hash), IsAdmin: true}
			if err := db.Create(&user).Error; err != nil {
				c.String(http.StatusInternalServerError, err.Error())
				return
			}
			token, _ := issueJWT(user)
			c.JSON(http.StatusOK, gin.H{"token": token, "user": user})
			return
		}
		var user User
		if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
			c.String(http.StatusUnauthorized, "invalid credentials")
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
			c.String(http.StatusUnauthorized, "invalid credentials")
			return
		}
		token, _ := issueJWT(user)
		c.JSON(http.StatusOK, gin.H{"token": token, "user": user})
	})

	// legacy secure group removed
	authGroup.GET("/nodes", func(c *gin.Context) {
		var settings Setting
		db.First(&settings)
		var nodes []Node
		db.Preload("Entries").Preload("Peers").Preload("Routes").Find(&nodes)
		for i := range nodes {
			ensureNodeToken(db, &nodes[i])
			if nodes[i].Transport == "" {
				nodes[i].Transport = settings.Transport
			}
			if nodes[i].Compression == "" {
				nodes[i].Compression = settings.Compression
			}
			if nodes[i].CompressionMin == 0 && settings.CompressionMin > 0 {
				nodes[i].CompressionMin = settings.CompressionMin
			}
		}
		c.JSON(http.StatusOK, nodes)
	})
	api.GET("/host/ips", authUserMiddleware(db), func(c *gin.Context) {
		resp := map[string]any{
			"interfaces": listPublicIfAddrs(),
		}
		if v4, v6 := detectPublicIPs(); v4 != "" || v6 != "" {
			resp["public_v4"] = v4
			resp["public_v6"] = v6
		}
		c.JSON(http.StatusOK, resp)
	})
	api.GET("/certs", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		if _, err := findNodeByToken(db, nodeToken); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		certPath := envOrDefault("AROUTER_CERT_PATH", "certs/arouter.crt")
		keyPath := envOrDefault("AROUTER_KEY_PATH", "certs/arouter.key")
		certData, err1 := os.ReadFile(certPath)
		keyData, err2 := os.ReadFile(keyPath)
		if err1 != nil || err2 != nil {
			// fallback to embedded defaults
			certData = defaultCert
			keyData = defaultKey
			if len(certData) == 0 || len(keyData) == 0 {
				c.String(http.StatusInternalServerError, fmt.Sprintf("cert read err=%v key err=%v", err1, err2))
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"cert": string(certData), "key": string(keyData)})
	})
	authGroup.POST("/nodes", func(c *gin.Context) {
		var req Node
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			c.String(http.StatusBadRequest, "name required")
			return
		}
		req.WSListen = defaultIfEmpty(req.WSListen, ":18080")
		req.MetricsListen = defaultIfEmpty(req.MetricsListen, ":19090")
		req.AuthKey = defaultIfEmpty(req.AuthKey, randomKey())
		req.InsecureSkipTLS = true
		req.RerouteAttempts = defaultInt(req.RerouteAttempts, 3)
		req.UDPSessionTTL = defaultIfEmpty(req.UDPSessionTTL, "60s")
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		ensureNodeToken(db, &req)
		c.JSON(http.StatusCreated, req)
	})
	authGroup.GET("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").Preload("Routes").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var settings Setting
		db.First(&settings)
		if node.Transport == "" {
			node.Transport = settings.Transport
		}
		if node.Compression == "" {
			node.Compression = settings.Compression
		}
		if node.CompressionMin == 0 && settings.CompressionMin > 0 {
			node.CompressionMin = settings.CompressionMin
		}
		c.JSON(http.StatusOK, node)
	})
	authGroup.PUT("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Node
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		updates := map[string]interface{}{
			"ws_listen":        defaultIfEmpty(req.WSListen, node.WSListen),
			"wss_listen":       defaultIfEmpty(req.WSSListen, node.WSSListen),
			"metrics_listen":   defaultIfEmpty(req.MetricsListen, node.MetricsListen),
			"poll_period":      defaultIfEmpty(req.PollPeriod, node.PollPeriod),
			"compression":      defaultIfEmpty(req.Compression, node.Compression),
			"compression_min":  req.CompressionMin,
			"transport":        defaultIfEmpty(req.Transport, node.Transport),
			"quic_listen":      defaultIfEmpty(req.QUICListen, node.QUICListen),
			"quic_server_name": defaultIfEmpty(req.QUICServerName, node.QUICServerName),
		}
		if err := db.Model(&node).Updates(updates).Error; err != nil {
			c.String(http.StatusBadRequest, "update failed: %v", err)
			return
		}
		db.Preload("Entries").Preload("Peers").Preload("Routes").First(&node, id)
		c.JSON(http.StatusOK, node)
	})
	authGroup.DELETE("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		db.Delete(&Peer{}, "node_id = ?", id)
		db.Delete(&Entry{}, "node_id = ?", id)
		db.Delete(&RoutePlan{}, "node_id = ?", id)
		db.Delete(&Node{}, "id = ?", id)
		c.Status(http.StatusNoContent)
	})
	authGroup.POST("/nodes/:id/entries", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Entry
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		req.NodeID = node.ID
		req.Proto = defaultIfEmpty(req.Proto, "tcp")
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	authGroup.DELETE("/nodes/:id/entries/:entryId", func(c *gin.Context) {
		id := c.Param("id")
		entryId := c.Param("entryId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := db.Delete(&Entry{}, "id = ? AND node_id = ?", entryId, id).Error; err != nil {
			c.String(http.StatusBadRequest, "delete failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})
	authGroup.POST("/nodes/:id/peers", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Peer
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		req.NodeID = node.ID
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	authGroup.PUT("/nodes/:id/peers/:peerId", func(c *gin.Context) {
		id := c.Param("id")
		pid := c.Param("peerId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Peer
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if err := db.Model(&Peer{}).Where("id = ? AND node_id = ?", pid, id).Updates(map[string]interface{}{
			"peer_name": req.PeerName,
			"entry_ip":  req.EntryIP,
			"exit_ip":   req.ExitIP,
			"endpoint":  req.Endpoint,
		}).Error; err != nil {
			c.String(http.StatusBadRequest, "update failed: %v", err)
			return
		}
		var peer Peer
		db.First(&peer, pid)
		c.JSON(http.StatusOK, peer)
	})
	authGroup.DELETE("/nodes/:id/peers/:peerId", func(c *gin.Context) {
		id := c.Param("id")
		pid := c.Param("peerId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := db.Delete(&Peer{}, "id = ? AND node_id = ?", pid, id).Error; err != nil {
			c.String(http.StatusBadRequest, "delete failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})

	authGroup.GET("/nodes/:id/routes", func(c *gin.Context) {
		id := c.Param("id")
		var routes []RoutePlan
		db.Where("node_id = ?", id).Order("priority asc, id asc").Find(&routes)
		c.JSON(http.StatusOK, routes)
	})
	api.GET("/node-routes/:name", func(c *gin.Context) {
		// 节点 token 校验
		nodeToken := getBearerToken(c)
		if _, err := findNodeByToken(db, nodeToken); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		name := c.Param("name")
		var node Node
		if err := db.Preload("Routes").Where("name = ?", name).First(&node).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		routes := make([]RouteConfig, 0, len(node.Routes))
		for _, r := range node.Routes {
			routes = append(routes, RouteConfig{
				Name:     r.Name,
				Exit:     r.Exit,
				Remote:   r.Remote,
				Priority: r.Priority,
				Path:     []string(r.Path),
			})
		}
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Priority == routes[j].Priority {
				return routes[i].Name < routes[j].Name
			}
			return routes[i].Priority < routes[j].Priority
		})
		c.JSON(http.StatusOK, gin.H{"routes": routes})
	})
	authGroup.POST("/nodes/:id/routes", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req RoutePlan
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		req.NodeID = node.ID
		if req.Priority == 0 {
			req.Priority = 1
		}
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	authGroup.PUT("/nodes/:id/routes/:routeId", func(c *gin.Context) {
		id := c.Param("id")
		rid := c.Param("routeId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req RoutePlan
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if err := db.Model(&RoutePlan{}).Where("id = ? AND node_id = ?", rid, id).Updates(map[string]any{
			"name":       req.Name,
			"exit":       req.Exit,
			"remote":     req.Remote,
			"priority":   req.Priority,
			"path":       req.Path,
			"updated_at": time.Now(),
		}).Error; err != nil {
			c.String(http.StatusBadRequest, "update failed: %v", err)
			return
		}
		var route RoutePlan
		db.First(&route, rid)
		c.JSON(http.StatusOK, route)
	})
	authGroup.DELETE("/nodes/:id/routes/:routeId", func(c *gin.Context) {
		id := c.Param("id")
		rid := c.Param("routeId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := db.Delete(&RoutePlan{}, "id = ? AND node_id = ?", rid, id).Error; err != nil {
			c.String(http.StatusBadRequest, "delete failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})

	api.POST("/metrics", func(c *gin.Context) {
		// 节点 token 校验
		nodeToken := getBearerToken(c)
		node, err := findNodeByToken(db, nodeToken)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var payload struct {
			From    string                     `json:"from"`
			Metrics map[string]LinkMetricsJSON `json:"metrics"`
			Status  struct {
				CPUUsage    float64  `json:"cpu_usage"`
				MemUsed     uint64   `json:"mem_used_bytes"`
				MemTotal    uint64   `json:"mem_total_bytes"`
				UptimeSec   uint64   `json:"uptime_sec"`
				NetInBytes  uint64   `json:"net_in_bytes"`
				NetOutBytes uint64   `json:"net_out_bytes"`
				Version     string   `json:"version"`
				Transport   string   `json:"transport"`
				Compression string   `json:"compression"`
				OS          string   `json:"os"`
				Arch        string   `json:"arch"`
				PublicIPs   []string `json:"public_ips"`
			} `json:"status"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		for to, m := range payload.Metrics {
			db.Model(&LinkMetric{}).Where("from_node = ? AND to_node = ?", payload.From, to).
				Assign(map[string]any{"rtt_ms": m.RTTms, "loss": m.Loss, "updated_at": time.Now()}).
				FirstOrCreate(&LinkMetric{
					From: payload.From, To: to, RTTMs: m.RTTms, Loss: m.Loss, UpdatedAt: time.Now(),
				})
		}
		// 更新节点自身状态
		db.Model(&Node{}).Where("id = ?", node.ID).Updates(map[string]any{
			"last_cpu":      payload.Status.CPUUsage,
			"mem_used":      payload.Status.MemUsed,
			"mem_total":     payload.Status.MemTotal,
			"uptime_sec":    payload.Status.UptimeSec,
			"net_in_bytes":  payload.Status.NetInBytes,
			"net_out_bytes": payload.Status.NetOutBytes,
			"node_version":  payload.Status.Version,
			"last_seen_at":  time.Now(),
			"transport":     firstNonEmpty(payload.Status.Transport, node.Transport),
			"compression":   firstNonEmpty(payload.Status.Compression, node.Compression),
			"os_name":       payload.Status.OS,
			"arch":          payload.Status.Arch,
			"public_ips":    StringList(payload.Status.PublicIPs),
		})
		c.Status(http.StatusNoContent)
	})

	api.POST("/probe/e2e", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		node, err := findNodeByToken(db, nodeToken)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var req struct {
			Route   string   `json:"route"`
			Path    []string `json:"path"`
			RTTMs   int64    `json:"rtt_ms"`
			Success bool     `json:"success"`
			Error   string   `json:"error"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if strings.TrimSpace(req.Route) == "" || len(req.Path) == 0 {
			c.String(http.StatusBadRequest, "route and path required")
			return
		}
		probe := RouteProbe{
			Node:    node.Name,
			Route:   req.Route,
			Path:    StringList(req.Path),
			RTTMs:   req.RTTMs,
			Success: req.Success,
			Error:   req.Error,
		}
		if err := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "node"}, {Name: "route"}},
			DoUpdates: clause.Assignments(map[string]interface{}{"path": probe.Path, "rtt_ms": probe.RTTMs, "success": probe.Success, "error": probe.Error, "updated_at": time.Now()}),
		}).Create(&probe).Error; err != nil {
			c.String(http.StatusInternalServerError, "save failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})

	authGroup.GET("/probes", func(c *gin.Context) {
		var probes []RouteProbe
		db.Order("updated_at desc").Find(&probes)
		c.JSON(http.StatusOK, probes)
	})

	api.GET("/topology", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		if _, err := findNodeByToken(db, nodeToken); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var rows []LinkMetric
		db.Find(&rows)
		edges := make(map[string]map[string]LinkMetricsJSON)
		for _, r := range rows {
			if edges[r.From] == nil {
				edges[r.From] = make(map[string]LinkMetricsJSON)
			}
			edges[r.From][r.To] = LinkMetricsJSON{RTTms: r.RTTMs, Loss: r.Loss, UpdatedAt: r.UpdatedAt}
		}
		c.JSON(http.StatusOK, gin.H{"edges": edges})
	})

	// 返回填充好的 config_pull.sh
	r.GET("/nodes/:id/config_pull.sh", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		// token 校验，与 config 相同策略
		tokenHeader := getBearerToken(c)
		if tokenHeader == "" {
			if t := c.Query("token"); t != "" {
				tokenHeader = "Bearer " + t
			}
		}
		if token := strings.TrimPrefix(tokenHeader, "Bearer "); token == "" || token != node.Token {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		installDir := c.Query("install_dir")
		if strings.TrimSpace(installDir) == "" {
			installDir = "/opt/arouter"
		}
		configURL := c.Query("config_url")
		if configURL == "" {
			if b64 := c.Query("config_url_b64"); b64 != "" {
				if data, err := base64.StdEncoding.DecodeString(b64); err == nil {
					configURL = string(data)
				}
			}
		}
		if configURL == "" {
			scheme := "http"
			if c.Request.TLS != nil {
				scheme = "https"
			}
			hostBase := scheme + "://" + c.Request.Host
			configURL = fmt.Sprintf("%s/nodes/%d/config?token=%s", hostBase, node.ID, url.QueryEscape(node.Token))
		}
		proxy := c.Query("proxy_prefix")
		tokenVal := c.Query("token_override")
		if tokenVal == "" {
			tokenVal = node.Token
		}
		script := renderConfigPullScript(installDir, configURL, tokenVal, proxy)
		c.Header("Content-Type", "text/x-shellscript")
		c.String(http.StatusOK, script)
	})

	// 生成节点 config.json
	r.GET("/nodes/:id/config", func(c *gin.Context) {
		nodeToken := c.GetHeader("Authorization")
		if nodeToken == "" {
			if t := c.Query("token"); t != "" {
				nodeToken = "Bearer " + t
			}
		}
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").Preload("Routes").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if node.Token == "" {
			ensureNodeToken(db, &node)
		}
		if token := strings.TrimPrefix(nodeToken, "Bearer "); token == "" || token != node.Token {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var all []Node
		db.Find(&all)
		settings := loadSettings(db)
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		base := scheme + "://" + c.Request.Host
		cfg := buildConfig(node, all, globalKey, base, settings)
		osHint := strings.ToLower(c.Query("os"))
		cfg = applyOSOverrides(cfg, osHint)
		if dir := c.Query("install_dir"); dir != "" {
			if strings.HasSuffix(dir, "/.arouter") {
				dir = strings.TrimSuffix(dir, "/.arouter")
			}
			cfg = applyInstallDirOverrides(cfg, dir)
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-config.json"`, node.Name))
		c.JSON(http.StatusOK, cfg)
	})

	// 生成节点安装脚本（内嵌 config，并包含后续自动拉取配置的 URL）
	r.GET("/nodes/:id/install.sh", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if node.Token == "" {
			ensureNodeToken(db, &node)
		}
		authHeader := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if authHeader == "" {
			authHeader = c.Query("token")
		}
		authorized := authHeader != "" && authHeader == node.Token
		if !authorized {
			if tok := getBearerToken(c); tok != "" {
				if claims, err := parseJWT(tok); err == nil {
					var u User
					if err := db.First(&u, claims.UserID).Error; err == nil {
						authorized = true
					}
				}
			}
		}
		if !authorized {
			// 最后兜底：如果没有用户存在且首次访问，直接允许下载
			var cnt int64
			db.Model(&User{}).Count(&cnt)
			if cnt == 0 {
				authorized = true
			}
		}
		if !authorized {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var all []Node
		db.Find(&all)
		settings := loadSettings(db)
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		base := scheme + "://" + c.Request.Host
		cfg := buildConfig(node, all, globalKey, base, settings)
		osHint := strings.ToLower(c.Query("os"))
		cfg = applyOSOverrides(cfg, osHint)
		data, _ := json.MarshalIndent(cfg, "", "  ")
		configURL := fmt.Sprintf("%s/nodes/%s/config?token=%s", base, id, url.QueryEscape(node.Token))
		configPullBase := fmt.Sprintf("%s/nodes/%s/config_pull.sh?token=%s", base, id, url.QueryEscape(node.Token))
		c.Header("Content-Type", "text/x-shellscript")
		c.Header("Content-Disposition", "attachment; filename=\"install.sh\"")
		syncInt := syncIntervalFromConfig(data)
		c.String(http.StatusOK, installScript(string(data), configURL, configPullBase, syncInt))
	})

	// 全局系统设置（传输/压缩）读写接口
	r.GET("/api/settings", authUserMiddleware(db), func(c *gin.Context) {
		c.JSON(http.StatusOK, loadSettings(db))
	})
	r.POST("/api/settings", authUserMiddleware(db), func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		var req Setting
		if err := c.BindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		var s Setting
		if err := db.First(&s).Error; err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		if strings.TrimSpace(req.Transport) != "" {
			s.Transport = strings.TrimSpace(req.Transport)
		}
		if strings.TrimSpace(req.Compression) != "" {
			s.Compression = strings.TrimSpace(req.Compression)
		}
		if req.CompressionMin >= 0 {
			s.CompressionMin = req.CompressionMin
		}
		s.DebugLog = req.DebugLog
		if strings.TrimSpace(req.HTTPProbeURL) != "" {
			s.HTTPProbeURL = strings.TrimSpace(req.HTTPProbeURL)
		}
		if err := db.Save(&s).Error; err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, s)
	})

	addr := envOrDefault("CONTROLLER_ADDR", ":8080")
	log.Printf("controller listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("controller run failed: %v", err)
	}
}

func buildConfig(node Node, allNodes []Node, globalKey string, controllerBase string, settings Setting) ConfigResponse {
	wsMap := make(map[string]string, len(allNodes))
	for _, n := range allNodes {
		// 若全局传输为 wss，则优先使用节点的 wss 监听端口
		if strings.EqualFold(settings.Transport, "wss") && strings.TrimSpace(n.WSSListen) != "" {
			wsMap[n.Name] = n.WSSListen
		} else {
			wsMap[n.Name] = defaultIfEmpty(n.WSListen, ":18080")
		}
	}
	peers := make(map[string]string, len(node.Peers))
	for _, p := range node.Peers {
		if p.PeerName != "" {
			ws := wsMap[p.PeerName]
			if ws == "" {
				ws = ":18080"
			}
			host := p.EntryIP
			if host == "" {
				host = p.PeerName
			}
			// IPv6需加[]
			if strings.Contains(host, ":") && !strings.Contains(host, "[") {
				host = "[" + host + "]"
			}
			port := ""
			if strings.HasPrefix(ws, ":") {
				port = strings.TrimPrefix(ws, ":")
			} else if strings.Contains(ws, ":") {
				parts := strings.Split(ws, ":")
				port = parts[len(parts)-1]
			} else {
				port = ws
			}
			if port == "" {
				port = "18080"
			}
			// 仅返回 host:port，由节点按 transport 组装协议
			peers[p.PeerName] = fmt.Sprintf("%s:%s", host, port)
		}
	}
	entries := make([]EntryConfig, 0, len(node.Entries))
	for _, e := range node.Entries {
		entries = append(entries, EntryConfig{
			Listen: e.Listen,
			Proto:  defaultIfEmpty(e.Proto, "tcp"),
			Exit:   e.Exit,
			Remote: e.Remote,
		})
	}
	routes := make([]RouteConfig, 0, len(node.Routes))
	for _, r := range node.Routes {
		routes = append(routes, RouteConfig{
			Name:     r.Name,
			Exit:     r.Exit,
			Remote:   r.Remote,
			Priority: r.Priority,
			Path:     []string(r.Path),
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Priority == routes[j].Priority {
			return routes[i].Name < routes[j].Name
		}
		return routes[i].Priority < routes[j].Priority
	})
	return ConfigResponse{
		ID:              node.Name,
		WSListen:        defaultIfEmpty(node.WSListen, ":18080"),
		WSSListen:       node.WSSListen,
		QUICListen:      defaultIfEmpty(node.QUICListen, node.WSListen),
		QUICServerName:  defaultIfEmpty(node.QUICServerName, "arouter.529851.xyz"),
		Peers:           peers,
		Entries:         entries,
		PollPeriod:      defaultIfEmpty(node.PollPeriod, "5s"),
		InsecureSkipTLS: true,
		AuthKey:         firstNonEmpty(globalKey, node.AuthKey, randomKey()),
		MetricsListen:   defaultIfEmpty(node.MetricsListen, ":19090"),
		RerouteAttempts: defaultInt(node.RerouteAttempts, 3),
		UDPSessionTTL:   defaultIfEmpty(node.UDPSessionTTL, "60s"),
		MTLSCert:        defaultIfEmpty(node.MTLSCert, "/opt/arouter/certs/arouter.crt"),
		MTLSKey:         defaultIfEmpty(node.MTLSKey, "/opt/arouter/certs/arouter.key"),
		MTLSCA:          node.MTLSCA,
		ControllerURL:   defaultIfEmpty(node.ControllerURL, controllerBase),
		Routes:          routes,
		Compression:     defaultIfEmpty(settings.Compression, "gzip"),
		CompressionMin:  defaultInt(settings.CompressionMin, node.CompressionMin),
		Transport:       defaultIfEmpty(settings.Transport, "quic"),
		DebugLog:        settings.DebugLog,
		TokenPath:       "/opt/arouter/.token",
		OS:              node.OSName,
		Arch:            node.Arch,
		HTTPProbeURL:    settings.HTTPProbeURL,
	}
}

func renderConfigPullScript(installDir, configURL, token, proxy string) string {
	if strings.TrimSpace(installDir) == "" {
		installDir = "/opt/arouter"
	}
	content := strings.ReplaceAll(configPullTemplate, "__INSTALL_DIR__", installDir)
	content = strings.ReplaceAll(content, "__CONFIG_URL__", configURL)
	content = strings.ReplaceAll(content, "__TOKEN__", token)
	content = strings.ReplaceAll(content, "__PROXY_PREFIX__", proxy)
	return content
}

type IfAddr struct {
	Iface string `json:"iface"`
	Addr  string `json:"addr"`
}

func listPublicIfAddrs() []IfAddr {
	ifaces, _ := net.Interfaces()
	var res []IfAddr
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
			res = append(res, IfAddr{Iface: iface.Name, Addr: ip.String()})
		}
	}
	return res
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
	// IPv6: unique local fc00::/7
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

func detectPublicIPs() (string, string) {
	client := &http.Client{Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v4 := fetchIP(ctx, client, "https://4.ipw.cn/")
	v6 := fetchIP(ctx, client, "https://6.ipw.cn/")
	return strings.TrimSpace(v4), strings.TrimSpace(v6)
}

func fetchIP(ctx context.Context, client *http.Client, url string) string {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	return string(b)
}

func installScript(configJSON string, configURL string, configPullBase string, syncInterval string) string {
	script := `#!/usr/bin/env bash
set -euo pipefail

NAME="arouter-node"
HOME_SAFE="${HOME:-}"
if [ -z "$HOME_SAFE" ]; then HOME_SAFE="$(eval echo ~${SUDO_USER:-$USER} 2>/dev/null || true)"; fi
if [ -z "$HOME_SAFE" ]; then HOME_SAFE="$(cd ~ 2>/dev/null && pwd || echo /tmp)"; fi
INSTALL_DIR_DEFAULT="/opt/arouter"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" = "darwin" ]; then INSTALL_DIR_DEFAULT="${HOME_SAFE}/.arouter"; fi
INSTALL_DIR="${INSTALL_DIR:-$INSTALL_DIR_DEFAULT}"
TOKEN=""
GITHUB_REPO="NiuStar/arouter"
ARCH=$(uname -m)
PROXY_PREFIX="${PROXY_PREFIX:-}"
if [ -n "$PROXY_PREFIX" ]; then
  PROXY_PREFIX="${PROXY_PREFIX%/}/"
fi

map_arch() {
  case "$1" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "unsupported" ;;
  esac
}
ARCH=$(map_arch "$ARCH")
if [ "$ARCH" = "unsupported" ]; then
  echo "Unsupported arch"; exit 1
fi

sudo mkdir -p "$INSTALL_DIR"
sudo chown "$(id -u)":"$(id -g)" "$INSTALL_DIR"
cd "$INSTALL_DIR"

CONFIG_URL="__CONFIG_URL__"

while getopts ":p:v:t:u:k:" opt; do
  case $opt in
    p) PROXY_PREFIX="$OPTARG" ;;
    v) AROUTER_VERSION="$OPTARG" ;;
    t) GITHUB_TOKEN="$OPTARG" ;;
    u) CONFIG_URL="$OPTARG" ;;
    k) TOKEN="$OPTARG" ;;
    *) ;;
  esac
done
shift $((OPTIND-1))

# append os hint to CONFIG_URL
if [[ "$CONFIG_URL" != *"os="* ]]; then
  if [[ "$CONFIG_URL" == *"?"* ]]; then SEP="&"; else SEP="?"; fi
  CONFIG_URL="${CONFIG_URL}${SEP}os=${OS}"
fi

# fetch config_pull.sh from controller
CONFIG_PULL_BASE="__CONFIG_PULL_BASE__"
CONFIG_B64=$(printf '%s' "$CONFIG_URL" | base64 | tr -d '\n')
CONFIG_PULL_URL="${CONFIG_PULL_BASE}&install_dir=${INSTALL_DIR}&config_url_b64=${CONFIG_B64}&proxy_prefix=${PROXY_PREFIX}&token_override=${TOKEN}"
echo "==> Fetching config_pull.sh..."
echo "$CONFIG_PULL_URL"
curl -v -fsSL "$CONFIG_PULL_URL" -o config_pull.sh
chmod +x config_pull.sh

echo "==> Writing config..."
cat > config.json <<'CONFIGEOF'
__CONFIG__
CONFIGEOF
echo "DEBUG: config.json written, size=$(stat -c%%s config.json 2>/dev/null || stat -f%%z config.json 2>/dev/null)" >&2
if [ "$OS" = "darwin" ]; then
  # 将默认的 /opt/arouter 路径重写为当前安装目录，便于证书/配置落在用户目录
  python3 - <<'PY'
import json, os, pathlib
cfg_path = pathlib.Path("config.json")
cfg = json.loads(cfg_path.read_text())
inst = os.environ.get("INSTALL_DIR", "/opt/arouter")
def repl(v):
    if isinstance(v, str) and v.startswith("/opt/arouter"):
        return v.replace("/opt/arouter", inst, 1)
    return v
for key in ("mtls_cert","mtls_key","mtls_ca","token_path"):
    if key in cfg:
        cfg[key] = repl(cfg[key])
cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
PY
  echo "DEBUG: config.json rewritten for darwin install dir ${INSTALL_DIR}" >&2
fi
# 展开 config.json 中的路径占位符（${HOME} 或 /opt/arouter -> INSTALL_DIR）
python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path("config.json")
cfg = json.loads(p.read_text())
home = os.environ.get("HOME","")
inst = os.environ.get("INSTALL_DIR","")
def expand(v):
    if not isinstance(v, str):
        return v
    if "${HOME}" in v and home:
        v = v.replace("${HOME}", home)
    if inst and v.startswith("/opt/arouter"):
        v = v.replace("/opt/arouter", inst, 1)
    return v
for key in ("mtls_cert","mtls_key","mtls_ca","token_path"):
    if key in cfg:
        cfg[key] = expand(cfg[key])
p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
PY
# Write token if provided
if [ -n "$TOKEN" ]; then
  echo "$TOKEN" > .token
  chmod 600 .token
fi
# Extract fields after args parsed
sync_interval() {
  val=$(grep -o '"poll_period"[[:space:]]*:[[:space:]]*"[^"]*"' config.json | head -n1 | sed 's/.*:"\\([^"]*\\)".*/\\1/')
  [ -z "$val" ] && val="60s"
  echo "$val"
}

detect_latest() {
  # Try GitHub API with optional token to avoid rate limit
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    echo "DEBUG: querying latest with token via ${PROXY_PREFIX}https://api.github.com/repos/${GITHUB_REPO}/releases/latest" >&2
    curl -fsSL --connect-timeout 10 --max-time 30 -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      "${PROXY_PREFIX}https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
      | grep -Eo '"tag_name":\s*"[^"]+"' | head -n1 | sed 's/.*"\(.*\)"/\1/' || true
  else
    echo "DEBUG: querying latest without token via ${PROXY_PREFIX}https://api.github.com/repos/${GITHUB_REPO}/releases/latest" >&2
    curl -fsSL --connect-timeout 10 --max-time 30 "${PROXY_PREFIX}https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
      | grep -Eo '"tag_name":\s*"[^"]+"' | head -n1 | sed 's/.*"\(.*\)"/\1/' || true
  fi
}

if [ -z "${AROUTER_VERSION:-}" ]; then
	echo "==> Detecting latest release..."
	AROUTER_VERSION=$(detect_latest)
  # Fallback: follow redirect from releases/latest
  if [ -z "${AROUTER_VERSION:-}" ]; then
    echo "DEBUG: fallback via redirect ${PROXY_PREFIX}https://github.com/${GITHUB_REPO}/releases/latest" >&2
    AROUTER_VERSION=$(curl -I -L -s "${PROXY_PREFIX}https://github.com/${GITHUB_REPO}/releases/latest" \
      | tr -d '\r' | awk -F/ '/^location: /{print $NF; exit}')
  fi
fi

if [ -z "${AROUTER_VERSION:-}" ]; then
	echo "Failed to detect latest release. Set AROUTER_VERSION=vX.Y.Z and rerun."
	echo "PROXY_PREFIX=${PROXY_PREFIX}"
	exit 1
else
	echo "==> Using release ${AROUTER_VERSION}"
fi

BIN_URL="https://github.com/${GITHUB_REPO}/releases/download/${AROUTER_VERSION}/arouter-${OS}-${ARCH}"
echo "==> Downloading binary ${BIN_URL}"
TMP_BIN=$(mktemp)
echo "DEBUG: downloading via ${PROXY_PREFIX}${BIN_URL}" >&2
if ! curl -fsSL -fL --connect-timeout 10 --max-time 60 "${PROXY_PREFIX}${BIN_URL}" -o "$TMP_BIN"; then
  status=$?
  echo "Download failed. Check version/arch or set AROUTER_VERSION manually."
  echo "DEBUG: curl exit code ${status} | PROXY_PREFIX=${PROXY_PREFIX}"
  exit 1
fi
chmod +x "$TMP_BIN"

HAS_SYSTEMCTL="$(command -v systemctl || true)"
IS_DARWIN=""
if [ "$OS" = "darwin" ]; then IS_DARWIN="1"; fi
echo "==> Stopping previous service (if exists)..."
if [ -n "$HAS_SYSTEMCTL" ]; then
	if systemctl is-active --quiet arouter; then
		sudo systemctl stop arouter || true
	fi
  sudo systemctl disable arouter || true
  sudo rm -f /etc/systemd/system/arouter.service
  sudo systemctl daemon-reload
fi

mv -f "$TMP_BIN" arouter

if [ -n "$HAS_SYSTEMCTL" ]; then
echo "==> Installing systemd service..."
SERVICE_FILE="/etc/systemd/system/arouter.service"
cat <<SERVICE | sudo tee "$SERVICE_FILE" >/dev/null
[Unit]
Description=ARouter Node
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/arouter -config ${INSTALL_DIR}/config.json
Environment=CONFIG_URL=${CONFIG_URL:-__CONFIG_URL__}
Environment=NODE_TOKEN=$(cat ${INSTALL_DIR}/.token 2>/dev/null || true)
Restart=always
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable arouter
sudo systemctl restart arouter
elif [ -n "$IS_DARWIN" ]; then
	PLIST="/Library/LaunchDaemons/com.arouter.node.plist"
	echo "==> Installing launchd service at ${PLIST}"
	cat <<PLIST | sudo tee "$PLIST" >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.arouter.node</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_DIR}/arouter</string>
    <string>-config</string>
    <string>${INSTALL_DIR}/config.json</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${INSTALL_DIR}/arouter.log</string>
  <key>StandardErrorPath</key><string>${INSTALL_DIR}/arouter.err</string>
</dict>
</plist>
PLIST
	sudo chown root:wheel "$PLIST"
	sudo chmod 644 "$PLIST"
	sudo launchctl unload "$PLIST" 2>/dev/null || true
	sudo launchctl load -w "$PLIST"
else
	echo "systemctl/launchctl not found, skipped service install. Binary placed at ${INSTALL_DIR}/arouter."
	echo "Please configure autostart manually."
fi

	HAS_LAUNCHCTL="$(command -v launchctl || true)"
	
	if [ -n "$HAS_SYSTEMCTL" ]; then
# 配置自动同步任务：周期拉取最新配置，变更则重启服务
echo "==> Installing config sync service..."
SYNC_SCRIPT="${INSTALL_DIR}/config_pull.sh"

cat <<SERVICE | sudo tee /etc/systemd/system/arouter-config.service >/dev/null
[Unit]
Description=ARouter Config Sync

[Service]
Type=oneshot
ExecStart=${SYNC_SCRIPT}
Environment=CONFIG_URL=${CONFIG_URL:-__CONFIG_URL__}
Environment=INSTALL_DIR=${INSTALL_DIR}
Environment=NODE_TOKEN=$(cat ${INSTALL_DIR}/.token 2>/dev/null || true)
User=root
SERVICE

cat <<SERVICE | sudo tee /etc/systemd/system/arouter-config.timer >/dev/null
[Unit]
Description=Run ARouter Config Sync periodically

[Timer]
OnBootSec=30s
OnUnitActiveSec=__SYNC_INTERVAL__

[Install]
WantedBy=timers.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable arouter-config.timer
sudo systemctl start arouter-config.timer

echo "==> Install complete. Service status:"
sudo systemctl status arouter --no-pager
elif [ -n "$IS_DARWIN" ]; then
	SYNC_SCRIPT="${INSTALL_DIR}/config_pull.sh"
	SYNC_SECS=$(echo "__SYNC_INTERVAL__" | sed 's/[^0-9]//g')
	[ -z "$SYNC_SECS" ] && SYNC_SECS=60
	PLIST="/Library/LaunchDaemons/com.arouter.config.plist"
	echo "==> Installing launchd timer for config sync (${SYNC_SECS}s)"
	cat <<PLIST | sudo tee "$PLIST" >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.arouter.config</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>${SYNC_SCRIPT}</string>
  </array>
  <key>StartInterval</key><integer>${SYNC_SECS}</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>${INSTALL_DIR}/config_pull.log</string>
  <key>StandardErrorPath</key><string>${INSTALL_DIR}/config_pull.err</string>
</dict>
</plist>
PLIST
	sudo chown root:wheel "$PLIST"
	sudo chmod 644 "$PLIST"
	sudo launchctl unload "$PLIST" 2>/dev/null || true
	sudo launchctl load -w "$PLIST"
	echo "==> Install complete. launchd services loaded (com.arouter.node, com.arouter.config)."
else
	echo "systemctl not found, skipping config sync timer install."
fi
`
	script = strings.ReplaceAll(script, "__CONFIG__", configJSON)
	script = strings.ReplaceAll(script, "__CONFIG_URL__", configURL)
	script = strings.ReplaceAll(script, "__CONFIG_PULL_BASE__", configPullBase)
	script = strings.ReplaceAll(script, "__SYNC_INTERVAL__", syncInterval)
	// choose installDir placeholder; script自身根据 OS 继续覆写为 /opt/arouter 或 $HOME/.arouter
	script = strings.ReplaceAll(script, "__INSTALL_DIR__", "/opt/arouter")
	return script
}

func mustOpenDB() *gorm.DB {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dbPath := envOrDefault("DB_PATH", "./data/arouter.db")
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
			log.Fatalf("create db dir failed: %v", err)
		}
		db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
		if err != nil {
			log.Fatalf("open sqlite failed: %v", err)
		}
		return db
	}
	if strings.HasPrefix(dsn, "sqlite:") {
		path := strings.TrimPrefix(dsn, "sqlite:")
		db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
		if err != nil {
			log.Fatalf("open sqlite failed: %v", err)
		}
		return db
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("open mysql failed: %v", err)
	}
	return db
}

func defaultIfEmpty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func defaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func randomKey() string {
	b := make([]byte, 16)
	_, _ = time.Now().UTC().MarshalBinary()
	for i := range b {
		b[i] = byte(65 + i)
	}
	return fmt.Sprintf("key-%d", time.Now().UnixNano())
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ensureGlobalSettings 确保全局设置存在（单行），默认从环境获取或使用内置值。
func ensureGlobalSettings(db *gorm.DB) {
	var cnt int64
	if err := db.Model(&Setting{}).Count(&cnt).Error; err != nil {
		log.Printf("count settings failed: %v", err)
		return
	}
	if cnt == 0 {
		def := Setting{
			Transport:      envOrDefault("GLOBAL_TRANSPORT", "quic"),
			Compression:    envOrDefault("GLOBAL_COMPRESSION", "none"),
			CompressionMin: 0,
			DebugLog:       false,
			HTTPProbeURL:   envOrDefault("GLOBAL_HTTP_PROBE_URL", "https://www.google.com/generate_204"),
		}
		if err := db.Create(&def).Error; err != nil {
			log.Printf("create default settings failed: %v", err)
		} else {
			log.Printf("created default global settings: %+v", def)
		}
	}
}

func loadSettings(db *gorm.DB) Setting {
	var s Setting
	if err := db.First(&s).Error; err != nil {
		log.Printf("load settings failed, using defaults: %v", err)
		return Setting{
			Transport:      envOrDefault("GLOBAL_TRANSPORT", "quic"),
			Compression:    envOrDefault("GLOBAL_COMPRESSION", "none"),
			CompressionMin: 0,
			DebugLog:       false,
			HTTPProbeURL:   envOrDefault("GLOBAL_HTTP_PROBE_URL", "https://www.google.com/generate_204"),
		}
	}
	if strings.TrimSpace(s.HTTPProbeURL) == "" {
		s.HTTPProbeURL = envOrDefault("GLOBAL_HTTP_PROBE_URL", "https://www.google.com/generate_204")
	}
	return s
}

func generateToken() string {
	b := make([]byte, 16)
	_, _ = time.Now().UTC().MarshalBinary()
	for i := range b {
		b[i] = byte(65 + i)
	}
	return fmt.Sprintf("tok-%d", time.Now().UnixNano())
}

func ensureNodeToken(db *gorm.DB, n *Node) {
	if n.Token == "" {
		n.Token = generateToken()
		db.Model(&Node{}).Where("id = ?", n.ID).Update("token", n.Token)
	}
}

func ensureAdminExists(db *gorm.DB, username, password string) {
	var cnt int64
	db.Model(&User{}).Count(&cnt)
	if cnt == 0 && username != "" && password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		db.Create(&User{Username: username, PasswordHash: string(hash), IsAdmin: true})
	}
}

func issueJWT(u User) (string, error) {
	claims := UserClaims{UserID: u.ID, IsAdmin: u.IsAdmin}
	b, _ := json.Marshal(claims)
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write(b)
	sig := mac.Sum(nil)
	return fmt.Sprintf("%s.%x", b, sig), nil
}

func parseJWT(token string) (*UserClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token")
	}
	b := []byte(parts[0])
	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write(b)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return nil, fmt.Errorf("invalid signature")
	}
	var claims UserClaims
	if err := json.Unmarshal(b, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func authUserMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		claims, err := parseJWT(token)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var user User
		if err := db.First(&user, claims.UserID).Error; err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("user", user)
		c.Next()
	}
}

func requireAdmin(c *gin.Context) {
	uVal, ok := c.Get("user")
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	u := uVal.(User)
	if !u.IsAdmin {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
}

func getBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func findNodeByToken(db *gorm.DB, token string) (*Node, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	var n Node
	if err := db.Where("token = ?", token).First(&n).Error; err != nil {
		return nil, err
	}
	return &n, nil
}

// ensureColumns 兜底补齐旧库缺失的字段，避免“no such column”。
func ensureColumns(db *gorm.DB) {
	type col struct {
		model interface{}
		name  string
		table string
		ctype string
	}
	cols := []col{
		{&Node{}, "quic_listen", "nodes", "TEXT"},
		{&Node{}, "transport", "nodes", "TEXT"},
		{&Node{}, "compression", "nodes", "TEXT"},
		{&Node{}, "compression_min", "nodes", "INTEGER"},
		{&Node{}, "quic_server_name", "nodes", "TEXT"},
		{&Node{}, "udp_session_ttl", "nodes", "TEXT"},
		{&Node{}, "controller_url", "nodes", "TEXT"},
		{&Node{}, "reroute_attempts", "nodes", "INTEGER"},
		{&Node{}, "insecure_skip_tls", "nodes", "BOOLEAN"},
		{&Node{}, "mtls_cert", "nodes", "TEXT"},
		{&Node{}, "mtls_key", "nodes", "TEXT"},
		{&Node{}, "mtls_ca", "nodes", "TEXT"},
		{&Node{}, "last_cpu", "nodes", "DOUBLE"},
		{&Node{}, "mem_used", "nodes", "BIGINT"},
		{&Node{}, "mem_total", "nodes", "BIGINT"},
		{&Node{}, "uptime_sec", "nodes", "BIGINT"},
		{&Node{}, "net_in_bytes", "nodes", "BIGINT"},
		{&Node{}, "net_out_bytes", "nodes", "BIGINT"},
		{&Node{}, "node_version", "nodes", "TEXT"},
		{&Node{}, "last_seen_at", "nodes", "DATETIME"},
		{&Node{}, "token", "nodes", "TEXT"},
		{&Node{}, "public_ips", "nodes", "TEXT"},
		{&User{}, "username", "users", "TEXT"},
		{&User{}, "password_hash", "users", "TEXT"},
		{&User{}, "is_admin", "users", "BOOLEAN"},
		{&Setting{}, "debug_log", "settings", "BOOLEAN"},
		{&Setting{}, "http_probe_url", "settings", "TEXT"},
		{&Peer{}, "entry_ip", "peers", "TEXT"},
		{&Peer{}, "exit_ip", "peers", "TEXT"},
	}
	for _, c := range cols {
		if !db.Migrator().HasColumn(c.model, c.name) {
			if err := db.Migrator().AddColumn(c.model, c.name); err != nil {
				log.Printf("add column %s via migrator failed: %v, trying raw alter", c.name, err)
				if err2 := addColumnRaw(db, c.table, c.name, c.ctype); err2 != nil {
					log.Printf("add column %s via raw alter failed: %v", c.name, err2)
				} else {
					log.Printf("added missing column %s via raw alter", c.name)
				}
			} else {
				log.Printf("added missing column %s", c.name)
			}
		}
	}
}

func addColumnRaw(db *gorm.DB, table, column, ctype string) error {
	dialect := strings.ToLower(db.Dialector.Name())
	switch dialect {
	case "sqlite":
		return db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, ctype)).Error
	case "mysql":
		mysqlType := ctype
		if strings.EqualFold(ctype, "BOOLEAN") {
			mysqlType = "TINYINT(1)"
		} else if strings.EqualFold(ctype, "TEXT") {
			mysqlType = "VARCHAR(255)"
		}
		return db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, mysqlType)).Error
	default:
		return fmt.Errorf("unsupported dialect %s", dialect)
	}
}

// Utility: allow simple JSON API as well
func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); strings.TrimSpace(v) != "" {
		return v
	}
	return def
}
