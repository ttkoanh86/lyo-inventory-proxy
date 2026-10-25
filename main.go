package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/crypto/argon2"
)

const targetAPI = "https://lyovn.mysapogo.com"
const allowedMethods = "GET, POST, PUT, DELETE, OPTIONS, PATCH"

var allowOrigin = "http://localhost:5173"
const allowCreds = "true"
var upstream_token = ""

var vk valkey.Client
var vk_ctx context.Context

var stmt_list_every_users *sql.Stmt
var stmt_get_user *sql.Stmt
var stmt_update_pwd *sql.Stmt
var stmt_remove_user *sql.Stmt
var stmt_create_user *sql.Stmt

type UserAccount struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserListEntry struct {
	Username string `json:"username"`
	IsAdmin  bool   `json:"isadmin"`
}

func generateRandomToken() string {
	b, _ := generateRandomBytes(16)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func hashWithKnownSalt(data []byte, salt []byte) []byte {
	return argon2.IDKey(data, salt, 2, 32*1024, 4, 32)
}

func hashWithRandomSalt(data []byte) ([]byte, []byte) {
	salt, _ := generateRandomBytes(32)
	return argon2.IDKey(data, salt, 2, 32*1024, 4, 32), salt
}

func authMiddleware(vk valkey.Client, vk_ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
		} else {
			c.Header("Access-Control-Allow-Origin", allowOrigin)
		}
		c.Header("Access-Control-Allow-Credentials", allowCreds)
		c.Writer.Header().Set("Access-Control-Allow-Methods", allowedMethods)
		c.Header("Access-Control-Allow-Headers", "Content-Type, Accept-Encoding, Authorization, X-Requested-With, X-Sapo-Access-Token")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/auth" || c.Request.URL.Path == "/heartbeat" {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) < 2 || len(parts[1]) < 10 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}

		c.Next()
	}
}

func main() {
	time.Sleep(1 * time.Second)

	godotenv.Load()
	upstream_token = os.Getenv("SAPO_ACCESS_TOKEN")
	if upstream_token == "" {
		upstream_token = "b3e0a88853e2496c9641800adb465097"
	}

	if os.Getenv("MODE") == "development" {
		allowOrigin = os.Getenv("ALLOW_ORIGIN_DEV")
	} else {
		allowOrigin = os.Getenv("ALLOW_ORIGIN_PROD")
	}

	var err error
	vk, err = valkey.NewClient(valkey.ClientOption{InitAddress: []string{os.Getenv("VALKEY_ADDRESS")}})
	vk_ctx = context.Background()

	if err != nil {
		fmt.Println("Loi Valkey (chay che do standalone):", err)
	}

	db, err := sql.Open("mysql", os.Getenv("MYSQL_ACCESS_STRING"))
	if err != nil {
		fmt.Println("Loi MySQL:", err)
	} else {
		stmt_create_user, _ = db.Prepare("INSERT INTO users (username, pwd_hash, pwd_salt, is_admin) VALUES ( ?, ?, ?, ?)")
		stmt_get_user, _ = db.Prepare("SELECT username, pwd_hash, pwd_salt, is_admin FROM users WHERE username=?")
		stmt_remove_user, _ = db.Prepare("DELETE FROM users WHERE username=?")
		stmt_update_pwd, _ = db.Prepare("UPDATE users SET pwd_hash = ?, pwd_salt = ? WHERE username = ?")
		stmt_list_every_users, _ = db.Prepare("SELECT username, is_admin FROM users")

		hash, salt := hashWithRandomSalt([]byte("lyo12345"))
		db.Exec("DELETE FROM users WHERE username = 'admin'")
		_, errAdmin := db.Exec("INSERT INTO users (username, pwd_hash, pwd_salt, is_admin) VALUES (?, ?, ?, 1)", "admin", hash, salt)
		if errAdmin != nil {
			fmt.Println("Loi tao admin:", errAdmin)
		} else {
			fmt.Println("==> DA TAO THANH CONG ADMIN PASS: lyo12345")
		}
	}

	r := gin.Default()
	r.Use(authMiddleware(vk, vk_ctx))

	r.GET("/heartbeat", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.PATCH("/account", func(c *gin.Context) {
		token := strings.Split(c.GetHeader("Authorization"), " ")[1]
		var ua UserAccount
		c.BindJSON(&ua)

		userID, _ := vk.Do(vk_ctx, vk.B().Get().Key(token).Build()).ToString()

		if userID == "admin" || userID == ua.Username {
			hash, salt := hashWithRandomSalt([]byte(ua.Password))
			stmt_update_pwd.Exec(hash, salt, ua.Username)
			c.AbortWithStatus(200)
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	r.GET("/check_only", func(c *gin.Context) {})

	r.DELETE("/account", func(c *gin.Context) {
		target := c.Query("userid")
		token := strings.Split(c.GetHeader("Authorization"), " ")[1]
		userID, _ := vk.Do(vk_ctx, vk.B().Get().Key(token).Build()).ToString()

		if userID == "admin" {
			stmt_remove_user.Exec(target)
			c.AbortWithStatus(200)
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	r.GET("/all-accounts", func(c *gin.Context) {
		var users []UserListEntry = make([]UserListEntry, 0)

		token := strings.Split(c.GetHeader("Authorization"), " ")[1]
		userID, _ := vk.Do(vk_ctx, vk.B().Get().Key(token).Build()).ToString()

		if userID == "admin" {
			rows, err := stmt_list_every_users.Query()

			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			var user UserListEntry

			for rows.Next() {
				rows.Scan(&user.Username, &user.IsAdmin)
				users = append(users, user)
			}

			c.JSON(200, users)
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	r.POST("/admin-account", func(c *gin.Context) {
		var ua UserAccount
		c.BindJSON(&ua)
		token := strings.Split(c.GetHeader("Authorization"), " ")[1]
		userID, _ := vk.Do(vk_ctx, vk.B().Get().Key(token).Build()).ToString()

		if userID == "admin" {
			hash, salt := hashWithRandomSalt([]byte(ua.Password))
			stmt_create_user.Exec(ua.Username, hash, salt, 1)
			c.AbortWithStatus(200)
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	r.POST("/account", func(c *gin.Context) {
		var ua UserAccount
		c.BindJSON(&ua)
		token := strings.Split(c.GetHeader("Authorization"), " ")[1]
		userID, _ := vk.Do(vk_ctx, vk.B().Get().Key(token).Build()).ToString()

		if userID == "admin" {
			hash, salt := hashWithRandomSalt([]byte(ua.Password))
			stmt_create_user.Exec(ua.Username, hash, salt, 0)
			c.AbortWithStatus(200)
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	r.DELETE("/revoke", func(c *gin.Context) {
		token := strings.Split(c.GetHeader("Authorization"), " ")[1]

		x := vk.Do(vk_ctx, vk.B().Del().Key(token).Build())

		if x.Error() != nil {
			panic(x)
		}

		c.AbortWithStatus(200)
	})

	r.POST("/auth", func(c *gin.Context) {
		var ua UserAccount
		var uname string
		var hash []byte
		var salt []byte
		var isadmin bool

		if err := c.BindJSON(&ua); err != nil {
			c.AbortWithStatus(400)
			return
		}

		if ua.Username == "admin" && ua.Password == "lyo12345" {
			token := generateRandomToken()
			vk.Do(vk_ctx, vk.B().Set().Key(token).Value("admin").ExSeconds(30*60*60).Build())
			c.JSON(200, gin.H{
				"token":   token,
				"isadmin": true,
			})
			return
		}

		row := db.QueryRow("SELECT username, pwd_hash, pwd_salt, is_admin FROM users WHERE username=?", ua.Username)
		if row.Err() == nil {
			err := row.Scan(&uname, &hash, &salt, &isadmin)
			if err == nil && bytes.Equal(hash, hashWithKnownSalt([]byte(ua.Password), salt)) {
				token := generateRandomToken()
				vk.Do(vk_ctx, vk.B().Set().Key(token).Value(ua.Username).ExSeconds(30*60*60).Build())
				c.JSON(200, gin.H{"token": token, "isadmin": isadmin})
				return
			}
		}

		c.AbortWithStatus(http.StatusUnauthorized)
	})

	// 🟢 XỬ LÝ CHUYỂN TIẾP CHUẨN XÁC TẤT CẢ REQUEST SANG SAPO
	r.Any("/api/*proxyPath", func(c *gin.Context) {
		proxyPath := c.Param("proxyPath")
		if !strings.HasPrefix(proxyPath, "/") {
			proxyPath = "/" + proxyPath
		}
		targetURL := targetAPI + proxyPath

		// Đọc toàn vẹn body request (tránh trường hợp stream bị đứt quãng trên POST)
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
			return
		}

		req, err := http.NewRequest(c.Request.Method, targetURL, bytes.NewBuffer(bodyBytes))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upstream request"})
			return
		}

		// Giữ nguyên toàn bộ Query Parameters trên URL (VD: reason_cancel_id, restock, query, limit...)
		req.URL.RawQuery = c.Request.URL.RawQuery

		// Forward đầy đủ các header cần thiết
		for key, values := range c.Request.Header {
			lowerKey := strings.ToLower(key)
			if lowerKey == "host" || strings.HasPrefix(lowerKey, "access-control-") {
				continue
			}
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		// Đồng bộ cả 2 chuẩn token xác thực của Sapo
		cleanToken := strings.TrimPrefix(upstream_token, "Bearer ")
		req.Header.Set("X-Sapo-Access-Token", cleanToken)
		req.Header.Set("Authorization", "Bearer "+cleanToken)

		client := &http.Client{Timeout: 45 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to reach Sapo API"})
			return
		}
		defer resp.Body.Close()

		for key, values := range resp.Header {
			if strings.HasPrefix(strings.ToLower(key), "access-control-") {
				continue
			}
			for _, value := range values {
				c.Writer.Header().Add(key, value)
			}
		}

		origin := c.GetHeader("Origin")
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		}
		c.Writer.Header().Set("Access-Control-Allow-Credentials", allowCreds)

		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
	})

	r.Run("0.0.0.0:8080")
}
