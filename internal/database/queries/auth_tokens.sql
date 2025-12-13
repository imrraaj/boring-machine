-- name: CreateToken :one
INSERT INTO auth_tokens (user_id, token, expires_at)
VALUES (?, ?, ?)
RETURNING *;

-- name: GetTokenByValue :one
SELECT * FROM auth_tokens
WHERE token = ? LIMIT 1;

-- name: UpdateLastUsed :exec
UPDATE auth_tokens
SET last_used_at = datetime('now')
WHERE id = ?;

-- name: DeleteToken :exec
DELETE FROM auth_tokens
WHERE id = ?;

-- name: DeleteExpiredTokens :execrows
DELETE FROM auth_tokens
WHERE expires_at < datetime('now');
