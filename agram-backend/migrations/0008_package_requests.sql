-- Migration: Package Requests Schema
-- Created on 2026-06-02

CREATE TABLE IF NOT EXISTS PackageRequests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    package_name TEXT NOT NULL,
    status TEXT DEFAULT 'pending', -- 'pending', 'approved', 'rejected'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Clients(id) ON DELETE CASCADE
);
