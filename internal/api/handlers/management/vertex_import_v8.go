package management

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/vertex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// ImportVertexCredentialV8 handles v8 management uploads for Vertex AI service-account
// JSON keys and Google Application Default Credentials (ADC) JSON files.
func (h *Handler) ImportVertexCredentialV8(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config unavailable"})
		return
	}
	if h.cfg.AuthDir == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth directory not configured"})
		return
	}

	fileHeader, errFile := c.FormFile("file")
	if errFile != nil {
		c.JSON(clienterror.HTTPStatusFromErrorOr(errFile, http.StatusBadRequest), gin.H{"error": "file required"})
		return
	}

	file, errOpen := fileHeader.Open()
	if errOpen != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to read file: %v", errOpen)})
		return
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			log.Errorf("vertex v8 import: failed to close uploaded file: %v", errClose)
		}
	}()

	data, errRead := io.ReadAll(file)
	if errRead != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to read file: %v", errRead)})
		return
	}

	var payload map[string]any
	if errUnmarshal := json.Unmarshal(data, &payload); errUnmarshal != nil || payload == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	authMode := strings.ToLower(strings.TrimSpace(firstNonEmpty(c.PostForm("auth_mode"), c.Query("auth_mode"))))
	if authMode != "" && authMode != "adc" && authMode != "service_account" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid auth_mode"})
		return
	}

	credType := strings.ToLower(strings.TrimSpace(valueAsString(payload["type"])))
	isADC := authMode == "adc" || (authMode == "" && credType != "" && credType != "service_account")

	ctx := context.Background()
	if reqCtx := c.Request.Context(); reqCtx != nil {
		ctx = reqCtx
	}

	if isADC {
		h.importVertexADCV8(c, ctx, data)
		return
	}

	h.importVertexServiceAccountV8(c, ctx, payload)
}

func (h *Handler) importVertexADCV8(c *gin.Context, ctx context.Context, data []byte) {
	project := firstNonEmpty(
		strings.TrimSpace(c.PostForm("project_id")),
		strings.TrimSpace(c.Query("project_id")),
		strings.TrimSpace(c.PostForm("project")),
		strings.TrimSpace(c.Query("project")),
	)
	location := firstNonEmpty(
		strings.TrimSpace(c.PostForm("location")),
		strings.TrimSpace(c.Query("location")),
	)
	prefix := firstNonEmpty(
		strings.TrimSpace(c.PostForm("prefix")),
		strings.TrimSpace(c.Query("prefix")),
	)
	quotaProject := firstNonEmpty(
		strings.TrimSpace(c.PostForm("quota_project_id")),
		strings.TrimSpace(c.Query("quota_project_id")),
		strings.TrimSpace(c.PostForm("quota_project")),
		strings.TrimSpace(c.Query("quota_project")),
	)

	record, errBuild := sdkAuth.BuildVertexADCAuth(ctx, h.cfg, data, &sdkAuth.LoginOptions{
		ProjectID: project,
		Metadata: map[string]string{
			"location":         location,
			"prefix":           prefix,
			"quota_project_id": quotaProject,
		},
	})
	if errBuild != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid vertex adc",
			"message": errBuild.Error(),
		})
		return
	}

	savedPath, errSave := h.saveTokenRecord(ctx, record)
	if errSave != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "save_failed",
			"message": errSave.Error(),
		})
		return
	}

	resp := gin.H{
		"status":     "ok",
		"auth-file":  savedPath,
		"project_id": valueAsString(record.Metadata["project_id"]),
		"location":   valueAsString(record.Metadata["location"]),
		"auth_mode":  "adc",
	}
	if quota := strings.TrimSpace(valueAsString(record.Metadata["quota_project_id"])); quota != "" {
		resp["quota_project_id"] = quota
	}
	if record.Prefix != "" {
		resp["prefix"] = record.Prefix
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) importVertexServiceAccountV8(c *gin.Context, ctx context.Context, serviceAccount map[string]any) {
	normalizedSA, errNorm := vertex.NormalizeServiceAccountMap(serviceAccount)
	if errNorm != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid service account",
			"message": errNorm.Error(),
		})
		return
	}
	serviceAccount = normalizedSA

	projectID := strings.TrimSpace(valueAsString(serviceAccount["project_id"]))
	if projectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id missing"})
		return
	}
	email := strings.TrimSpace(valueAsString(serviceAccount["client_email"]))

	location := firstNonEmpty(
		strings.TrimSpace(c.PostForm("location")),
		strings.TrimSpace(c.Query("location")),
	)
	if location == "" {
		location = "us-central1"
	}

	prefix := strings.Trim(firstNonEmpty(
		strings.TrimSpace(c.PostForm("prefix")),
		strings.TrimSpace(c.Query("prefix")),
	), "/")
	if strings.ContainsAny(prefix, "/\\\r\n\x00 ") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "prefix must be a single segment"})
		return
	}

	baseName := sanitizeVertexFilePart(projectID)
	if prefix != "" {
		baseName = sanitizeVertexFilePart(prefix) + "-" + baseName
	}
	fileName := fmt.Sprintf("vertex-%s.json", baseName)
	label := labelForVertex(projectID, email)

	storage := &vertex.VertexCredentialStorage{
		ServiceAccount: serviceAccount,
		ProjectID:      projectID,
		Email:          email,
		Location:       location,
		Prefix:         prefix,
		Type:           "vertex",
	}
	metadata := map[string]any{
		"service_account": serviceAccount,
		"project_id":      projectID,
		"email":           email,
		"location":        location,
		"prefix":          prefix,
		"type":            "vertex",
		"label":           label,
	}
	record := &coreauth.Auth{
		ID:       fileName,
		Provider: "vertex",
		FileName: fileName,
		Prefix:   prefix,
		Storage:  storage,
		Label:    label,
		Metadata: metadata,
	}

	savedPath, errSave := h.saveTokenRecord(ctx, record)
	if errSave != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "save_failed",
			"message": errSave.Error(),
		})
		return
	}

	resp := gin.H{
		"status":     "ok",
		"auth-file":  savedPath,
		"project_id": projectID,
		"email":      email,
		"location":   location,
		"auth_mode":  "service_account",
	}
	if prefix != "" {
		resp["prefix"] = prefix
	}
	c.JSON(http.StatusOK, resp)
}
