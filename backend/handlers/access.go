package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm/clause"

	"health-metrics-vault/middleware"
	"health-metrics-vault/models"
)

type grantAccessRequest struct {
	DoctorID uint `json:"doctor_id" binding:"required,gt=0"`
}

// GrantAccess handles POST /api/access (patient only).
//
// SECURITY:
//   - patient_id is taken from the JWT, never from the body: a patient can only
//     grant access to THEIR OWN records (no IDOR on consent).
//   - The target must be an existing user with role 'doctor'; a patient cannot
//     grant access to another patient.
//   - Idempotent: the composite unique index + ON CONFLICT DO NOTHING prevents duplicates.
func (h *Handler) GrantAccess(c *gin.Context) {
	var req grantAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: 'doctor_id' is required"})
		return
	}
	patientID := middleware.GetUserID(c)

	var doctor models.User
	if err := h.DB.Where("id = ? AND role = ?", req.DoctorID, models.RoleDoctor).First(&doctor).Error; err != nil {
		if isNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "doctor not found"})
			return
		}
		log.Printf("grant access: db error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	grant := models.DoctorAccess{DoctorID: doctor.ID, PatientID: patientID}
	if err := h.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&grant).Error; err != nil {
		log.Printf("grant access: db error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "access granted", "doctor_id": doctor.ID, "patient_id": patientID})
}

// RevokeAccess handles DELETE /api/access/:doctor_id (patient only).
// Least privilege: consent must be revocable at any time by the data owner.
// The WHERE clause is scoped to the caller's own patient_id, so a patient can
// never delete someone else's grant.
func (h *Handler) RevokeAccess(c *gin.Context) {
	doctorID, err := strconv.ParseUint(c.Param("doctor_id"), 10, 32)
	if err != nil || doctorID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid doctor_id"})
		return
	}
	patientID := middleware.GetUserID(c)

	res := h.DB.Where("doctor_id = ? AND patient_id = ?", uint(doctorID), patientID).Delete(&models.DoctorAccess{})
	if res.Error != nil {
		log.Printf("revoke access: db error: %v", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such grant"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "access revoked"})
}
