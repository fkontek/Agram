-- Migration: Add SentReminders table for strict email deduplication
-- Created on 2026-08-04

CREATE TABLE IF NOT EXISTS SentReminders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  target_date TEXT NOT NULL,
  reminder_type TEXT NOT NULL DEFAULT '24h_booking',
  sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, target_date, reminder_type)
);
