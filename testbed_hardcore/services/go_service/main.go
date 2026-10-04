package main

import (
	"fmt"
	"net/http"
	"github.com/gin-gonic/gin"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	TenantID string `json:"tenant_id"`
}

func main() {
	r := gin.Default()

	// 1. Go Blind Timing SQLi endpoint
	r.POST("/api/v1/go/query", func(c *gin.Context) {
		filter := c.Query("filter")
		// Vulnerable raw query
		query := fmt.Sprintf("SELECT * FROM audit_logs WHERE action = '%s'", filter)
		c.JSON(http.StatusOK, gin.H{"status": "executed", "query": query})
	})

	// 2. Go BOLA tenant violation endpoint
	r.GET("/api/v1/go/vault/:id", func(c *gin.Context) {
		id := c.Param("id")
		// Vulnerable: returns record without verifying tenant boundary
		c.JSON(http.StatusOK, gin.H{
			"id": id,
			"secret": "go-vault-encrypted-master-key",
			"tenant_id": "tenant-corp-99",
		})
	})

	r.Run(":18087")
}
