-- Add reset_token_hash and reset_token_expires columns to Clients table for secure password reset flow
ALTER TABLE Clients ADD COLUMN reset_token_hash TEXT;
ALTER TABLE Clients ADD COLUMN reset_token_expires INTEGER;
