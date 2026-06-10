-- Migration: Add reminder_sent Column to Bookings table
-- Created on 2026-06-10

ALTER TABLE Bookings ADD COLUMN reminder_sent INTEGER DEFAULT 0;
