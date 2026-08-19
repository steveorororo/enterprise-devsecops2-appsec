// Defective on purpose. Command injection and reflected cross-site scripting reachable from
// request input, used to prove static analysis reports on this repository's supported
// languages.
const express = require('express');
const { exec } = require('child_process');

const app = express();

app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, stdout) => {
    res.send(stdout);
  });
});

app.get('/echo', (req, res) => {
  res.send('<div>' + req.query.message + '</div>');
});

module.exports = app;
