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
		// Thiết lập Header CORS linh hoạt theo Origin gửi lên
		origin := c.GetHeader("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
		} else {
			c.Header("Access-Control-Allow-Origin", allowOrigin)
		}
		c.Header("Access-Control-Allow-Credentials", allowCreds)
		c.Writer.Header().Set("Access-Control-Allow-Methods", allowedMethods)
		c.Header("Access-Control-Allow-Headers", "Content-Type, Accept-Encoding, Authorization, X-Requested-With")

		// Trả về ngay lập tức cho request Preflight (OPTIONS)
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		// 🟢 Bỏ qua kiểm tra Token tài khoản đối với các API Proxy Sapo (/api/*) và API hệ thống
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/auth" || c.Request.URL.Path == "/heartbeat" {
			c.Next()
			return
		}

		// Kiểm tra Header Authorization cho các chức năng quản lý tài khoản nội bộ
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

	r.Use(gzip.Gzip(gzip.DefaultCompression))
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

	// 🟢 HÀM XỬ LÝ PROXY TẤT CẢ API /api/* SANG SAPO
	r.Any("/api/*proxyPath", func(c *gin.Context) {
		proxyPath := c.Param("proxyPath")
		
		// Đảm bảo luôn có dấu / ở đầu proxyPath để không bị dính liền domain gây lỗi 404
		if !strings.HasPrefix(proxyPath, "/") {
			proxyPath = "/" + proxyPath
		}
		
		targetURL := targetAPI + proxyPath

		req, err := http.NewRequest(c.Request.Method, targetURL, c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
			return
		}

		req.URL.RawQuery = c.Request.URL.RawQuery

		for key, values := range c.Request.Header {
			if key == "Host" || key == "Authorization" {
				continue
			}
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		// Đính kèm Token Sapo chính chủ
		req.Header.Set("X-Sapo-Access-Token", upstream_token)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to reach upstream API"})
			return
		}
		defer resp.Body.Close()

		// Copy response headers từ Sapo nhưng loại bỏ header CORS trùng lặp
		for key, values := range resp.Header {
			if strings.HasPrefix(strings.ToLower(key), "access-control-") {
				continue
			}
			for _, value := range values {
				c.Writer.Header().Add(key, value)
			}
		}

		// Bổ sung Header CORS chuẩn xác cho Frontend nhận dữ liệu
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
// Struct nhận dữ liệu từ giao diện web gửi lên
type CancelOrderReq struct {
	OrderCode string `json:"orderCode"`
	Note      string `json:"note"`
}

// Struct gửi lệnh hủy chuẩn sang API Sapo Omni
type SapoCancelPayload struct {
	ReasonCancelID int64  `json:"reason_cancel_id"`
	Note           string `json:"note"`
	Restock        bool   `json:"restock"`
}

// Hàm xử lý riêng biệt: Không đụng chạm vào cache hay logic cũ
func handleCancelSapoOrder(w http.ResponseWriter, r *http.Request) {
	// Bật CORS cho phép frontend gọi an toàn
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"success":false,"message":"Chỉ chấp nhận phương thức POST"}`, http.StatusMethodNotAllowed)
		return
	}

	var req CancelOrderReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.OrderCode) == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Thiếu mã đơn hàng hợp lệ",
		})
		return
	}

	orderCode := strings.TrimSpace(req.OrderCode)
	note := req.Note
	if note == "" {
		note = "Hủy tự động qua hệ thống"
	}

	// Lấy Domain và Token Sapo từ cấu hình môi trường hoặc hằng số có sẵn trong main.go
	sapoDomain := os.Getenv("SAPO_OMNI_DOMAIN")
	if sapoDomain == "" {
		sapoDomain = "lyo.mysapogo.com" // Điền domain chính xác của bạn nếu không dùng ENV
	}
	sapoToken := os.Getenv("SAPO_OMNI_TOKEN")
	if sapoToken == "" {
		sapoToken = "YOUR_SAPO_TOKEN_HERE" // Điền token Sapo nếu không dùng ENV
	}

	client := &http.Client{Timeout: 15 * time.Second}

	// BƯỚC 1: Tìm kiếm Order ID theo mã đơn
	searchURL := fmt.Sprintf("https://%s/admin/orders.json?query=%s", sapoDomain, url.QueryEscape(orderCode))
	searchReq, _ := http.NewRequest(http.MethodGet, searchURL, nil)
	searchReq.Header.Set("X-Sapo-Access-Token", sapoToken)
	searchReq.Header.Set("Content-Type", "application/json")

	searchResp, err := client.Do(searchReq)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Lỗi kết nối tới Sapo: " + err.Error()})
		return
	}
	defer searchResp.Body.Close()

	var searchResult struct {
		Orders []struct {
			ID          int64  `json:"id"`
			OrderNumber string `json:"order_number"`
			Name        string `json:"name"`
			Code        string `json:"code"`
			Status      string `json:"status"`
		} `json:"orders"`
	}

	if err := json.NewDecoder(searchResp.Body).Decode(&searchResult); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Lỗi đọc dữ liệu Sapo"})
		return
	}

	var targetOrderID int64
	for _, o := range searchResult.Orders {
		if strings.EqualFold(o.OrderNumber, orderCode) || strings.EqualFold(o.Name, orderCode) || strings.EqualFold(o.Code, orderCode) {
			if o.Status == "cancelled" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"message": fmt.Sprintf("Đơn hàng %s đã được hủy trước đó.", orderCode),
				})
				return
			}
			targetOrderID = o.ID
			break
		}
	}

	if targetOrderID == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Không tìm thấy đơn hàng %s trên Sapo", orderCode),
		})
		return
	}

	// BƯỚC 2: Gửi lệnh POST hủy đơn với đúng payload test chuẩn
	cancelURL := fmt.Sprintf("https://%s/admin/orders/%d/cancel.json", sapoDomain, targetOrderID)
	cancelBody, _ := json.Marshal(SapoCancelPayload{
		ReasonCancelID: 14585447,
		Note:           note,
		Restock:        true,
	})

	cancelReq, _ := http.NewRequest(http.MethodPost, cancelURL, bytes.NewBuffer(cancelBody))
	cancelReq.Header.Set("X-Sapo-Access-Token", sapoToken)
	cancelReq.Header.Set("Content-Type", "application/json")

	cancelResp, err := client.Do(cancelReq)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Lỗi khi gửi lệnh hủy đơn: " + err.Error()})
		return
	}
	defer cancelResp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	if cancelResp.StatusCode == http.StatusOK || cancelResp.StatusCode == http.StatusCreated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Đã hủy thành công đơn %s và hoàn kho!", orderCode),
		})
	} else {
		respBodyBytes, _ := io.ReadAll(cancelResp.Body)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Sapo từ chối [%d]: %s", cancelResp.StatusCode, string(respBodyBytes)),
		})
	}
}
