-- Remove auto-increment from backgrounds table
ALTER TABLE backgrounds ALTER COLUMN id DROP IDENTITY IF EXISTS;

-- Remove auto-increment from gift_cards table
ALTER TABLE gift_cards ALTER COLUMN id DROP IDENTITY IF EXISTS;
