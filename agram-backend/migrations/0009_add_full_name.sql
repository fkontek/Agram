-- Migration: Add Full Name Column to Clients table
-- Created on 2026-06-02

ALTER TABLE Clients ADD COLUMN full_name TEXT;
