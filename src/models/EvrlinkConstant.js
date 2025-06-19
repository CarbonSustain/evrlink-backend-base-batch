const { DataTypes } = require("sequelize");
const sequelize = require("../../db/db_config");

const EvrlinkConstant = sequelize.define(
  "EvrlinkConstant",
  {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    tax_rate: { type: DataTypes.FLOAT },
    evrlink_platform_fee: { type: DataTypes.FLOAT },
    climate_rate: { type: DataTypes.FLOAT },
    created_at: { type: DataTypes.DATE, field: "created_at" },
    updated_at: { type: DataTypes.DATE, field: "updated_at" },
  },
  {
    tableName: "evrlink_constants",
    timestamps: true,
    createdAt: "created_at",
    updatedAt: "updated_at",
  }
);

module.exports = EvrlinkConstant;
