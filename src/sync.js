// filepath: c:\Users\Chandan Bhat\OneDrive\Desktop\Evrlink2\backend\src\sync.js
const sequelize = require("../db/db_config");
const Background = require("./models/Background");
const GiftCard = require("./models/GiftCard");
const Transaction = require("./models/Transaction");
const User = require("./models/User");

const syncDatabase = async () => {
  try {
    await sequelize.authenticate();
    console.log("✅ Database connected successfully.");
    await sequelize.sync({ alter: true }); // Use { force: true } to drop and recreate tables
    console.log("✅ All models were synchronized successfully.");
  } catch (error) {
    console.error("❌ Unable to connect to the database:", error);
  } finally {
    await sequelize.close();
  }
};

syncDatabase();
