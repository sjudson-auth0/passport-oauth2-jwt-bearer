#!/usr/bin/env node

var jws = require('jws')
  , fs = require('fs');


var payload = {
  iss: 'https://jwt-idp.example.com',
  sub: 'mailto:mike@example.com',
  aud: 'https://jwt-rp.example.net',
  exp: 7702588800
};

var data = jws.sign({
  header: { alg: 'RS256' },
  payload: payload,
  privateKey: fs.readFileSync('../keys/rsa/private-key.pem')
});

console.log(data);
