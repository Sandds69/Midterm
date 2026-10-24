package handlers

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"health-metrics-vault/crypto"
	"health-metrics-vault/middleware"
	"health-metrics-vault/models"
)

const maxRecordChars = 10000

type createRecordRequest struct {
	// NOTE: there is intentionally NO patient_id field. The owner is always taken
	// from the verified JWT, so a patient cannot write records into another
	// patient's file (mass-assignment / IDOR on write).
	Data string `json:"data" binding:"required"`
}

type recordResponse struct {
	ID        uint      `json:"id"`
	PatientID uint      `json:"patient_id"`
	Data      string    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateRecord handles POST /api/records (patient only).
//
// SECURITY (Data at Rest): the plaintext medical data is encrypted with
// AES-256-GCM using the key from AES_ENCRYPTION_KEY BEFORE it reaches the DB.
func (h *Handler) CreateRecord(c *gin.Context) {
	var req createRecordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: 'data' is required"})
		return
	}
	req.Data = strings.TrimSpace(req.Data)
	if req.Data == "" || utf8.RuneCountInString(req.Data) > maxRecordChars {
		c.JSON(http.StatusBadRequest, gin.H{"error": "data must be 1-10000 characters"})
		return
	}

	patientID := middleware.GetUserID(c) // identity from the token, never from the client

	// Encrypting Data at Rest.
	encrypted, err := crypto.EncryptAESGCM(req.Data, h.Cfg.AESKey)
	if err != nil {
		log.Printf("create record: encryption error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	rec := models.MedicalRecord{PatientID: patientID, EncryptedData: encrypted}
	if err := h.DB.Create(&rec).Error; err != nil {
		log.Printf("create record: db error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusCreated, recordResponse{ID: rec.ID, PatientID: rec.PatientID, Data: req.Data, CreatedAt: rec.CreatedAt})
}

// GetRecords handles GET /api/records/:patient_id.
//
// SECURITY (IDOR mitigation / object-level authorization):
//   - Patient: may only read their OWN records -> token.user_id must equal :patient_id.
//   - Doctor:  may only read records of patients who EXPLICITLY granted access ->
//     a DoctorAccess row (doctor_id = token.user_id, patient_id = :patient_id) must exist.
//   - Anything else is denied (deny-by-default).
//
// Changing the ID in the URL is therefore useless to an attacker.
func (h *Handler) GetRecords(c *gin.Context) {
	requestedID, err := strconv.ParseUint(c.Param("patient_id"), 10, 32)
	if err != nil || requestedID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid patient_id"})
		return
	}
	patientID := uint(requestedID)
	userID := middleware.GetUserID(c)

	switch middleware.GetRole(c) {
	case models.RolePatient:
		// Mitigating IDOR here: a patient can only access their own file.
		if userID != patientID {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
			return
		}

	case models.RoleDoctor:
		// Mitigating IDOR here: enforce explicit patient consent.
		// Parameterized query -> safe from SQL injection.
		var count int64
		if err := h.DB.Model(&models.DoctorAccess{}).
			Where("doctor_id = ? AND patient_id = ?", userID, patientID).
			Count(&count).Error; err != nil {
			log.Printf("get records: access check error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		if count == 0 {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
			return
		}

	default:
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	var records []models.MedicalRecord
	if err := h.DB.Where("patient_id = ?", patientID).Order("created_at DESC").Find(&records).Error; err != nil {
		log.Printf("get records: db error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Decrypt only AFTER authorization has succeeded.
	out := make([]recordResponse, 0, len(records))
	for _, r := range records {
		plain, err := crypto.DecryptAESGCM(r.EncryptedData, h.Cfg.AESKey)
		if err != nil {
			// GCM authentication failed: wrong key or the row was tampered with.
			// Log the record ID (not the content) and fail closed.
			log.Printf("get records: integrity/decryption failure on record %d: %v", r.ID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		out = append(out, recordResponse{ID: r.ID, PatientID: r.PatientID, Data: plain, CreatedAt: r.CreatedAt})
	}

	c.JSON(http.StatusOK, gin.H{"patient_id": patientID, "records": out})
}

// isNotFound is a small helper for gorm.ErrRecordNotFound.
func isNotFound(err error) bool { return errors.Is(err, gorm.ErrRecordNotFound) }
