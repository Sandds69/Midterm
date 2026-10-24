// Package database opens the PostgreSQL connection and runs migrations.
package database

import (
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"health-metrics-vault/models"
)

// Connect opens a pooled connection to PostgreSQL and auto-migrates the schema.
//
// SECURITY: GORM uses parameterized queries / prepared statements for all
// Where("col = ?", value) calls, which mitigates SQL injection. The logger is set
// to Warn so SQL with bound values (which could include PII) is not logged.
func Connect(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	if err := db.AutoMigrate(&models.User{}, &models.MedicalRecord{}, &models.DoctorAccess{}); err != nil {
		return nil, err
	}
	return db, nil
}
