'use strict'

// client.js
const http = require('http');

// Define the server details
const options = {
    hostname: 'localhost',  // Target server (replace with actual hostname if needed)
    port: 3000,             // Port where the server is running
    path: '/',              // Path of the request (can be modified as needed)
    method: 'GET',          // HTTP method (GET in this case)
};

// Create an HTTP request
const req = http.request(options, (res) => {
    let data = '';

    // Collect response data
    res.on('data', (chunk) => {
        data += chunk;
    });

    // Once the response ends, log the response data
    res.on('end', () => {
        console.log('Server Response:', data);
    });
});

// Handle errors in case the request fails
req.on('error', (err) => {
    console.log('Request Error:', err);
});

// Send the request
req.end();
