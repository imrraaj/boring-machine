-- name: CreateToken :one
INSERT INTO auth_tokens (user_id, token, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetTokenByValue :one
SELECT * FROM auth_tokens
WHERE token = $1 LIMIT 1;

-- name: UpdateLastUsed :exec
UPDATE auth_tokens
SET last_used_at = NOW()
WHERE id = $1;

-- name: DeleteToken :exec
DELETE FROM auth_tokens
WHERE id = $1;

-- name: DeleteExpiredTokens :execrows
DELETE FROM auth_tokens
WHERE expires_at < NOW();
