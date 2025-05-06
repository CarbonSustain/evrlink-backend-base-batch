const sequelize = require('./db_config');
const Background = require('../src/models/Background');
// Import other models as needed

async function syncDatabase() {
  try {
    console.log('Connecting to database...');
    await sequelize.authenticate();
    console.log('Connection established successfully.');
    
    console.log('Syncing database models...');
    // Force: true will drop the tables and recreate them
    await sequelize.sync({ force: true });
    console.log('Database tables synchronized successfully');
    
    process.exit(0);
  } catch (error) {
    console.error('Database synchronization error:', error);
    process.exit(1);
  }
}

syncDatabase(); 