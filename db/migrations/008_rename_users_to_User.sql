-- First check if users table exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') THEN
        -- Rename users table to "User" (with quotes)
        ALTER TABLE users RENAME TO "User";
    END IF;
END $$; 