-- Migration: Instagram Integration Schema
-- Created on 2026-05-26

CREATE TABLE IF NOT EXISTS Settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS InstagramPosts (
    id TEXT PRIMARY KEY,
    caption TEXT,
    media_type TEXT,
    media_url TEXT,
    permalink TEXT,
    thumbnail_url TEXT,
    timestamp TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
