const { DataTypes } = require('sequelize');
const sequelize = require('../../db/db_config');

const user_role = sequelize.define('user_role', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
        field: 'id'
    },
    name: {
        type: DataTypes.STRING,
        field: 'name',
        allowNull: false,
        unique: true
    },
    created_at: {
        type: DataTypes.DATE,
        field: 'created_at',
        defaultValue: sequelize.literal('CURRENT_TIMESTAMP')
    },
    updated_at: {
        type: DataTypes.DATE,
        field: 'updated_at',
        defaultValue: sequelize.literal('CURRENT_TIMESTAMP')
    },

}, {
    tableName: 'user_role',
});

user_role.beforeValidate((user, options) => {
    return true;
});

module.exports = user_role;
