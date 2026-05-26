-- Migration: Add status and questionnaire columns to Clients table
-- Created on 2026-05-26

ALTER TABLE Clients ADD COLUMN status TEXT DEFAULT 'approved';
ALTER TABLE Clients ADD COLUMN questionnaire TEXT DEFAULT NULL;
