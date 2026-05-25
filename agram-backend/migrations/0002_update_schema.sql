-- Migration: Update Schema for tracking packages, attendance status, and training types.
-- Created on 2026-05-25

-- Add columns to Clients table
ALTER TABLE Clients ADD COLUMN package_name TEXT;
ALTER TABLE Clients ADD COLUMN total_credits INTEGER DEFAULT 0;
ALTER TABLE Clients ADD COLUMN remaining_credits INTEGER DEFAULT 0;
ALTER TABLE Clients ADD COLUMN package_expires TEXT;

-- Add status column to Bookings table (0 = reserved, 1 = attended, -1 = no-show)
ALTER TABLE Bookings ADD COLUMN status INTEGER DEFAULT 0;

-- Add type column to Sessions table ('grupni', 'poluindividualni', 'privatni')
ALTER TABLE Sessions ADD COLUMN type TEXT DEFAULT 'grupni';
