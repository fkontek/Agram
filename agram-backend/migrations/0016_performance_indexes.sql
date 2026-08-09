-- Create performance indexes for frequent query patterns
CREATE INDEX IF NOT EXISTS idx_bookings_user_status ON Bookings(user_id, status);
CREATE INDEX IF NOT EXISTS idx_bookings_session_status ON Bookings(session_id, status);
CREATE INDEX IF NOT EXISTS idx_sessions_date ON Sessions(date);
CREATE INDEX IF NOT EXISTS idx_waitlists_session ON Waitlists(session_id);
CREATE INDEX IF NOT EXISTS idx_clients_status ON Clients(status);
