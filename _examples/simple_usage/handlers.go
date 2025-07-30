// file: _examples/simple_usage/handlers.go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

// === Handlers cho nghiệp vụ "Đơn từ" ===

func (app *App) approveRequestHandler(c *gin.Context) {
	// Lấy ID từ path parameter của Gin
	requestID := c.Param("request_id")
	fullResourceID := "/requests/" + requestID

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Action Succeeded: Request '%s' has been approved.", fullResourceID),
	})
}

// === Handlers cho Quản lý Policy (PAP) ===

type policyRequest struct {
	Rules [][]string `json:"rules"`
}

func (app *App) addPoliciesHandler(c *gin.Context) {
	var req policyRequest
	// Dùng ShouldBindJSON để parse body request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	log.Printf("ADMIN API: Adding %d policies", len(req.Rules))
	ok, err := app.PolicyManager.AddPolicies(req.Rules)
	if err != nil || !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add policies"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Policies added successfully."})
}

func (app *App) getPoliciesHandler(c *gin.Context) {
	policies, err := app.PolicyManager.GetPolicies()
	if err != nil {
		log.Printf("ADMIN API: Failed to get policies: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve policies"})
		return
	}
	c.JSON(http.StatusOK, policies)
}
