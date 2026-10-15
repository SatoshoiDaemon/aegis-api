CREATE TABLE "oidc_records" (
  "model" TEXT NOT NULL, "id" TEXT NOT NULL, "payload" JSONB NOT NULL,
  "uid" TEXT, "grantId" TEXT, "accountId" TEXT, "expiresAt" TIMESTAMP(3), "consumedAt" INTEGER,
  CONSTRAINT "oidc_records_pkey" PRIMARY KEY ("model", "id")
);
CREATE INDEX "oidc_records_model_uid_idx" ON "oidc_records"("model", "uid");
CREATE INDEX "oidc_records_grantId_idx" ON "oidc_records"("grantId");
CREATE INDEX "oidc_records_accountId_idx" ON "oidc_records"("accountId");
CREATE INDEX "oidc_records_expiresAt_idx" ON "oidc_records"("expiresAt");
