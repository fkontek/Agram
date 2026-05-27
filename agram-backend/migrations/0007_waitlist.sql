-- Migration: Waitlist Schema
-- Created on 2026-05-27

CREATE TABLE IF NOT EXISTS Waitlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id, user_id),
    FOREIGN KEY (session_id) REFERENCES Sessions(id),
    FOREIGN KEY (user_id) REFERENCES Clients(id)
);
