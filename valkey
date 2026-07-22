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

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/crypto/argon2"
)

const targetAPI = "https://lyochuyenhanghanquoc.mysapogo.com" // Replace with your actual API
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
	return base64.RawStdEncoding.EncodeToString(b)
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

		c.Header("Access-Control-Allow-Origin", allowOrigin)
		c.Header("Access-Control-Allow-Credentials", allowCreds)
		c.Writer.Header().Set("Access-Control-Allow-Methods", allowedMethods)

		c.Header("Access-Control-Allow-Headers", "Content-Type, Accept-Encoding, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
		}

		fmt.Println(c.Request.URL.Path)
		if c.Request.URL.Path == "/auth" || c.Request.URL.Path == "/heartbeat" {
			c.Next()
			return
		} else if c.Request.URL.Path == "/check_only" {
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			authKey := strings.Split(authHeader, " ")[1]

			u := vk.Do(vk_ctx, vk.B().Get().Key(authKey).Build())
			us, err := u.ToString()

			if err != nil || us == "" {
				c.AbortWithStatus(http.StatusForbidden)
				return
			} else {
				c.AbortWithStatus(http.StatusAccepted)
			}
		} else {
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			authKey := strings.Split(authHeader, " ")[1]
			u := vk.Do(vk_ctx, vk.B().Get().Key(authKey).Build())
			us, err := u.ToString()

			if err != nil || us == "" {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
				return
			}

			// vk.Do(vk_ctx, vk.B().Set().Key(authKey).Value(us)(30*60*60).Build())

			c.Next()
		}

	}
}

func main() {
	time.Sleep(1 * time.Second)

	godotenv.Load()
	upstream_token = os.Getenv("SAPO_ACCESS_TOKEN")

	if os.Getenv("MODE") == "development" {
		allowOrigin = os.Getenv("ALLOW_ORIGIN_DEV")
	} else {
		allowOrigin = os.Getenv("ALLOW_ORIGIN_PROD")
	}

	// Connect to Valkey server
	// code cu: vk, err = valkey.NewClient(valkey.ClientOption{InitAddress: []string{os.Getenv("VALKEY_ADDRESS")}})
	var err error
	vk, err = valkey.NewClient(valkey.ClientOption{InitAddress: []string{os.Getenv("VALKEY_ADDRESS")}})
	vk_ctx = context.Background()

	if err != nil {
		panic(err)
	}

	// Connect to database server
	db, err := sql.Open("mysql", os.Getenv("MYSQL_ACCESS_STRING"))
	if err != nil {
		panic(err)
	}

	stmt_create_user, err = db.Prepare("INSERT INTO users (username, pwd_hash, pwd_salt, is_admin) VALUES ( ?, ?, ?, ?)")

	stmt_get_user, err = db.Prepare("SELECT username, pwd_hash, pwd_salt, is_admin FROM users WHERE username=?")

	stmt_remove_user, err = db.Prepare("DELETE FROM users WHERE username=?")

	stmt_update_pwd, err = db.Prepare("UPDATE users SET pwd_hash = ?, pwd_salt = ? WHERE username = ?")

	stmt_list_every_users, err = db.Prepare("SELECT username, is_admin FROM users")

// Tự động khởi tạo tài khoản admin nếu chưa có
	go func() {
		time.Sleep(2 * time.Second)
		hash, salt := hashWithRandomSalt([]byte("lyo12345"))
		db.Exec("DELETE FROM users WHERE username = 'admin'")
		_, err := db.Exec("INSERT INTO users (username, pwd_hash, pwd_salt, is_admin) VALUES (?, ?, ?, 1)", "admin", hash, salt)
		if err == nil {
			fmt.Println("==> DA TAO THANH CONG ADMIN PASS: lyo12345")
		}
	}()
	r := gin.Default()

	// Enable Gzip compression for all
	r.Use(gzip.Gzip(gzip.DefaultCompression))

	// Add authentication middleware
	r.Use(authMiddleware(vk, vk_ctx))

	r.GET("/heartbeat", func(c *gin.Context) {
		c.JSON(200, gin.H{})
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

	r.GET("/check_only", func(c *gin.Context) {

	})

	r.DELETE("/account", func(c *gin.Context) {

		c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", allowCreds)

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

		c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", allowCreds)

		var users []UserListEntry = make([]UserListEntry, 0)

		token := strings.Split(c.GetHeader("Authorization"), " ")[1]
		userID, _ := vk.Do(vk_ctx, vk.B().Get().Key(token).Build()).ToString()

		if userID == "admin" {
			rows, err := stmt_list_every_users.Query()

			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
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
		c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", allowCreds)

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

		c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", allowCreds)

		var ua UserAccount
		c.BindJSON(&ua)
		token := strings.Split(c.GetHeader("Authorization"), " ")[1]
		userID, _ := vk.Do(vk_ctx, vk.B().Get().Key(token).Build()).ToString()
		fmt.Println(userID)
		if userID == "admin" {
			hash, salt := hashWithRandomSalt([]byte(ua.Password))
			stmt_create_user.Exec(ua.Username, hash, salt, 0)
			c.AbortWithStatus(200)
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

	})

	r.DELETE("/revoke", func(c *gin.Context) {

		c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", allowCreds)

		token := strings.Split(c.GetHeader("Authorization"), " ")[1]

		x := vk.Do(vk_ctx, vk.B().Del().Key(token).Build())

		if x.Error() != nil {
			panic(x)
		}

		c.AbortWithStatus(200)

	})

	r.POST("/auth", func(c *gin.Context) {

		c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", allowCreds)
		c.Writer.Header().Set("Access-Control-Allow-Methods", allowedMethods)

		var ua UserAccount
		var uname string
		var hash []byte
		var salt []byte
		var isadmin bool
		c.BindJSON(&ua)
		row := stmt_get_user.QueryRow(ua.Username)
		verifyOnly := c.Query("verifyOnly") == "true"

		if row.Err() == nil {

			err := row.Scan(&uname, &hash, &salt, &isadmin)
			if err != nil {
				// panic(err)
				c.AbortWithStatus(401)
			}

			if bytes.Equal(hash, hashWithKnownSalt([]byte(ua.Password), salt)) {

				// 1: unprivileged account
				// 2: privileged account

				if verifyOnly {
					c.JSON(200, gin.H{})
				} else {
					token := generateRandomToken()
					if isadmin {
						vk.Do(vk_ctx, vk.B().Set().Key(token).Value("admin").ExSeconds(30*60*60).Build())
					} else {
						vk.Do(vk_ctx, vk.B().Set().Key(token).Value(ua.Username).ExSeconds(30*60*60).Build())
					}

					c.JSON(200, gin.H{"token": token, "isadmin": isadmin})
				}

			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}

		} else {

			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// row.Close()

	})

	// Proxy all /api/* requests to the target API
	r.Any("/api/*proxyPath", func(c *gin.Context) {

		c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", allowCreds)
		c.Writer.Header().Set("Access-Control-Allow-Methods", allowedMethods)

		proxyPath := c.Param("proxyPath")
		targetURL := targetAPI + proxyPath

		req, err := http.NewRequest(c.Request.Method, targetURL, c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
			return
		}

		// Copy query params
		req.URL.RawQuery = c.Request.URL.RawQuery

		// Copy headers
		for key, values := range c.Request.Header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		req.Header.Set("X-Sapo-Access-Token", upstream_token)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {

			c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to reach upstream API"})
			return
		} else {
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				c.Writer.Header().Add(key, value)
			}
		}

		// Set status and forward the response body
		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
	})

	r.Run("0.0.0.0:8080")
}
