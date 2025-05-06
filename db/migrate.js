const { Sequelize } = require('sequelize');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const sequelize = new Sequelize(
  process.env.DATABASE_NAME,
  process.env.DATABASE_USER,
  process.env.DATABASE_PASSWORD,
  {
    host: process.env.DATABASE_HOST,
    port: process.env.DATABASE_PORT,
    dialect: 'postgres',
  }
);

async function runMigration() {
  try {
    // First run our custom rename migration for users table
    console.log('Running migration to rename users table to "User"...');
    const renameMigrationPath = path.join(__dirname, 'migrations', '008_rename_users_to_User.sql');
    const renameMigrationSQL = fs.readFileSync(renameMigrationPath, 'utf8');
    await sequelize.query(renameMigrationSQL);
    console.log('Rename migration completed.');
    
    // Then apply other migrations
    await sequelize.query('ALTER TABLE backgrounds ADD COLUMN IF NOT EXISTS category VARCHAR(255);');
    console.log('Other migrations completed.');
    
    console.log('✅ Migration completed successfully');
    process.exit(0);
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  }
}

runMigration();
