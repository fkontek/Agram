-- Migration: Add has_seen_onboarding column to Clients table
-- Created on 2026-07-27

ALTER TABLE Clients ADD COLUMN has_seen_onboarding INTEGER DEFAULT 0;
