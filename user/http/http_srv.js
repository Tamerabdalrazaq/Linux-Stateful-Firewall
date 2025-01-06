// index.js
const express = require('express');
const app = express();
const port = 800;

// Middleware to parse incoming JSON requests (optional, depending on your needs)
app.use(express.json());

// Capture all incoming HTTP requests, regardless of the method or path
app.all('*', (req, res) => {
    // Log the incoming request details to the console
    console.log(`Received ${req.method} request to ${req.url}`);
    console.log('Request Body:', req.body);
    console.log('Request Headers:', req.headers);

    // Respond back to the client
    res.send('Request received. Check the console for details.');
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
