require('dotenv').config({ path: '/home/rabbany/Desktop/Auth-backend/.env' });
const mysql = require('mysql2/promise');

async function run() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '1',
    database: process.env.DB_NAME || 'night_warden',
    port: parseInt(process.env.DB_PORT || '3306')
  });
  
  const [rows] = await connection.query("SELECT id, name, version, client_secret FROM apps");
  console.log(rows);
  await connection.end();
}
run();
