const express = require('express');
const mysql = require('mysql2');
const { Keychain } = require('./password-manager'); // Assuming Keychain class is in a separate file
const { subtle } = require('crypto').webcrypto;
const path = require('path');  // Required to serve static files

const app = express();
const port = 3000;

// MySQL connection setup
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'roots',  // Replace with your MySQL root password
  database: 'password_manager_db',  // Replace with your database name
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err.stack);
    return;
  }
  console.log('Connected to the database as ID ' + db.threadId);
});

app.use(express.json());

// Serve static files from the root directory
app.use(express.static(path.join(__dirname)));

// Route for serving the registration page (index.html)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html')); // Serve the index.html from the parent folder
});

// Register endpoint for storing the user's password
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required' });
  }

  try {
    // Log before keychain initialization
    console.log('Initializing Keychain...');
    const keychain = await Keychain.init(password);  // Ensure Keychain.init() returns the necessary data
    console.log('Keychain initialized:', keychain);  // Log the keychain data to see what it contains

    // Export the master key into raw format
    console.log('Exporting master key...');
    const masterKeyBuffer = await subtle.exportKey('raw', keychain.secrets.masterKey);
    const masterKeyBase64 = Buffer.from(masterKeyBuffer).toString('base64');
    console.log('Master key exported:', masterKeyBase64);

    // Store the username and masterKey in the database
    const query = 'INSERT INTO users (username, masterKey) VALUES (?, ?)';
    db.execute(query, [username, masterKeyBase64], (err, results) => {
      if (err) {
        console.error('Database error:', err);  // Log the actual database error
        return res.status(500).json({ success: false, message: 'Database error', error: err.message });
      }
      console.log('User registered successfully:', results);
      res.status(200).json({ success: true, message: 'User registered successfully' });
    });
  } catch (error) {
    console.error('Error during password processing:', error);  // Log the error to the console
    res.status(500).json({ success: false, message: 'Error while processing password', error: error.message });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
