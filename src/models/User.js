const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");
const UserRole = require("./UserRole");

// Define the User model with schema-compliant fields
const User = sequelize.define(
  "users",
  {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    role_id: {
      type: DataTypes.INTEGER,
      field: "role_id",
      references: { model: "user_role", key: "id" },
    },
    wallet_address: {
      type: DataTypes.STRING,
      unique: true,
      field: "wallet_address",
    },
    username: { type: DataTypes.STRING },
    email: { type: DataTypes.STRING },
    created_at: { type: DataTypes.DATE, field: "created_at" },
    updated_at: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "users",
    timestamps: true,
    created_at: "created_at",
    updated_at: "updated_at",
  }
);

// Define associations
User.belongsTo(UserRole, { foreignKey: "role_id" });

module.exports = User;
