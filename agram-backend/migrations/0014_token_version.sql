-- Add token_version column to Clients table for server-side session revocation
ALTER TABLE Clients ADD COLUMN token_version INTEGER DEFAULT 1;
