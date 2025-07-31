// file: _examples/simple_usage/main.go
package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/duclek15/go-abac-library/abac"
	"github.com/gin-gonic/gin"
)

type App struct {
	Authorizer    *abac.Authorizer
	PolicyManager *abac.PolicyManager
}

// authMiddleware được viết lại theo chuẩn của Gin.
func (app *App) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}
		subjectID := strings.TrimPrefix(authHeader, "Bearer ")

		// Lấy resource và action từ context của Gin
		requestID := c.Param("request_id")
		resourceID := "/requests/" + requestID
		action := "approve_level_2" // Mặc định cho route này

		log.Printf("PEP: Check(Subject: %s, Resource: %s, Action: %s)", subjectID, resourceID, action)
		envAtt := abac.Attributes{}
		isAllowed, err := app.Authorizer.Check("*", subjectID, resourceID, action, envAtt)
		if err != nil || !isAllowed {
			log.Printf("PEP: DENIED. Reason: %v", err)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}

		log.Println("PEP: PERMITTED.")
		c.Next() // Cho phép request đi tiếp vào handler
	}
}

func main() {
	// --- Khởi tạo các thành phần (giữ nguyên) ---
	userRepo := &UserRepo{}
	docRepo := &DocumentRepo{}
	authorizer, policyManager, err := abac.NewABACSystemFromFile(
		"casbin_config/abac_model.conf",
		"casbin_config/abac_policy.csv",
		userRepo,
		docRepo,
	)
	if err != nil {
		log.Fatalf("FATAL: Could not create ABAC system: %v", err)
	}
	app := &App{
		Authorizer:    authorizer,
		PolicyManager: policyManager,
	}

	// --- Thiết lập Router với Gin ---
	router := gin.Default()

	// Nhóm các API quản lý policy
	adminAPI := router.Group("/admin")
	{
		adminAPI.POST("/policies", app.addPoliciesHandler)
		adminAPI.GET("/policies", app.getPoliciesHandler)
		adminAPI.DELETE("/policies", app.getPoliciesHandler)
	}

	// Nhóm các API nghiệp vụ "Đơn từ"
	requestAPI := router.Group("/requests")
	// Áp dụng middleware (PEP) cho group này
	requestAPI.Use(app.authMiddleware())
	{
		// Sử dụng path parameter :request_id
		requestAPI.POST("/:request_id/approve", app.approveRequestHandler)
	}

	// --- Hướng dẫn sử dụng ---
	printInstructions()

	// --- Khởi động server Gin ---
	log.Println("Gin server starting on :8080...")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Gin server failed to start: %v", err)
	}
}

func printInstructions() {
	log.Println("\n--- 🚀 Step 1: Bootstrap Policies via API ---")
	log.Println("Run this command in a new terminal to add business rules:")
	log.Println(`
curl -X POST -H "Content-Type: application/json" -d '{
  "rules": [
    ["Action == \"approve_level_2\" && Subject.role == \"hr_manager\" && Subject.tenant == \"tenant1\" && Subject.tenant == Resource.tenant", "allow"],
    ["Action == \"approve_level_2\" && Subject.role == \"hr_manager\" && Subject.tenant == \"tenant2\" && Subject.tenant == Resource.tenant && Resource.department == \"hr\"", "allow"]
  ]
}' http://localhost:8080/admin/policies
	`)

	log.Println("\n--- ✅ Step 2: Test Successful Scenarios ---")
	log.Println("  - [PASS] T1 HR Manager approves a request from Engineering dept in T1:")
	log.Println(`    curl -i -X POST -H "Authorization: Bearer t1_hr_manager" http://localhost:8080/requests/t1_eng_leave_001/approve`)
	log.Println("  - [PASS] T2 HR Manager approves a request from HR department in T2:")
	log.Println(`    curl -i -X POST -H "Authorization: Bearer t2_hr_manager" http://localhost:8080/requests/t2_hr_leave_001/approve`)

	log.Println("\n--- ❌ Step 3: Test Failed Scenarios ---")
	log.Println("  - [FAIL] T2 HR Manager CANNOT approve a request from Sales department in T2:")
	log.Println(`    curl -i -X POST -H "Authorization: Bearer t2_hr_manager" http://localhost:8080/requests/t2_sales_ot_002/approve`)

	log.Println("\n--- 🔍 (Optional) Step 4: View all current policies ---")
	log.Println("  - See all policies currently in memory:")
	log.Println(`    curl http://localhost:8080/admin/policies | jq .`)
}
