DROP INDEX "sessions_refresh_token_hash_idx";
DROP INDEX "email_tokens_token_hash_idx";
CREATE UNIQUE INDEX "sessions_refresh_token_hash_key" ON "sessions"("refresh_token_hash");
CREATE UNIQUE INDEX "email_tokens_token_hash_key" ON "email_tokens"("token_hash");
