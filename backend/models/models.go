// Package models defines the PostgreSQL schema (via GORM auto-migration).
package models

import "time"

// Role is the RBAC role of a user in the Mini-IAM.
type Role string

const (
	RolePatient Role = "patient"
	RoleDoctor  Role = "doctor"
)

// Valid reports whether r is one of the allowed roles.
func (r Role) Valid() bool {
	return r == RolePatient || r == RoleDoctor
}

// User is an identity in the Mini-IAM.
//
// SECURITY:
//   - PasswordHash is tagged `json:"-"` so it can never be accidentally serialized
//     into an API response.
//   - A DB-level CHECK constraint restricts role to 'patient' | 'doctor', so even a
//     bug in application code cannot create a privileged/unknown role.
type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Email        string    `gorm:"size:255;uniqueIndex;not null" json:"email"`
	PasswordHash string    `gorm:"not null" json:"-"`
	Role         Role      `gorm:"type:varchar(16);not null;check:chk_users_role,role IN ('patient','doctor')" json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// MedicalRecord stores a patient's PII / health data.
//
// SECURITY (Data at Rest): EncryptedData holds base64(nonce||AES-256-GCM ciphertext||tag).
// The plaintext is NEVER persisted. It is also hidden from JSON (`json:"-"`);
// handlers return a decrypted DTO instead.
type MedicalRecord struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	PatientID     uint      `gorm:"not null;index" json:"patient_id"`
	Patient       User      `gorm:"foreignKey:PatientID;constraint:OnDelete:CASCADE" json:"-"`
	EncryptedData string    `gorm:"type:text;not null" json:"-"`
	CreatedAt     time.Time `json:"created_at"`
}

// DoctorAccess is an explicit consent grant: patient PatientID allows doctor
// DoctorID to read their records. No row => no access (deny by default).
//
// The composite unique index prevents duplicate grants.
type DoctorAccess struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	DoctorID  uint      `gorm:"not null;uniqueIndex:idx_doctor_patient" json:"doctor_id"`
	Doctor    User      `gorm:"foreignKey:DoctorID;constraint:OnDelete:CASCADE" json:"-"`
	PatientID uint      `gorm:"not null;uniqueIndex:idx_doctor_patient;index" json:"patient_id"`
	Patient   User      `gorm:"foreignKey:PatientID;constraint:OnDelete:CASCADE" json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName pins the table name to "doctor_access".
func (DoctorAccess) TableName() string { return "doctor_access" }
