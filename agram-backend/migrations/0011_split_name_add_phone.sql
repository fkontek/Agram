-- Migration: Split Name and Add Phone Number to Clients table
-- Created on 2026-06-10

ALTER TABLE Clients ADD COLUMN first_name TEXT;
ALTER TABLE Clients ADD COLUMN last_name TEXT;
ALTER TABLE Clients ADD COLUMN phone TEXT;

-- Populate existing clients' first_name and last_name from full_name if possible
UPDATE Clients 
SET 
  first_name = CASE 
    WHEN INSTR(full_name, ' ') > 0 THEN SUBSTR(full_name, 1, INSTR(full_name, ' ') - 1)
    ELSE full_name 
  END,
  last_name = CASE 
    WHEN INSTR(full_name, ' ') > 0 THEN SUBSTR(full_name, INSTR(full_name, ' ') + 1)
    ELSE '' 
  END
WHERE full_name IS NOT NULL AND first_name IS NULL;
