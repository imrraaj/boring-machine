package auth

import (
	"boring-machine/internal/database/sqlc"
	"context"
	"fmt"
	"time"
)

type Validator struct {
	queries *sqlc.Queries
}

func NewValidator(queries *sqlc.Queries) *Validator {
	return &Validator{queries: queries}
}

// ValidateToken validates a token and returns the user ID
func (v *Validator) ValidateToken(ctx context.Context, tokenStr string) (int64, error) {
	// Get token from database
	token, err := v.queries.GetTokenByValue(ctx, tokenStr)
	if err != nil {
		return 0, fmt.Errorf("invalid token")
	}

	// Check if expired
	if time.Now().After(token.ExpiresAt.Time) {
		return 0, fmt.Errorf("token expired")
	}

	// Update last used timestamp (async, don't block)
	go v.queries.UpdateLastUsed(context.Background(), token.ID)

	return token.UserID, nil
}
