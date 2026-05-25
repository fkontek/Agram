-- Migration to create ActivityLogs table for Agram Pilates
CREATE TABLE ActivityLogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    details TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
