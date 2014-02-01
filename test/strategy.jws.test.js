var chai = require('chai')
  , fs = require('fs')
  , Strategy = require('../lib/passport-oauth2-jwt-bearer/strategy');


describe('Strategy', function() {
  
  var strategy = new Strategy(
    { audience: 'https://jwt-rp.example.net' },
    function(issuer, done) {
      if (issuer != 'https://jwt-idp.example.com') { return done('unexpected issuer'); }
      return fs.readFile(__dirname + '/keys/rsa/cert.pem', 'utf8', done);
    },
    function(issuer, subject, done) {
      return done(null, { id: '1234', issuer: issuer, subject: subject });
    }
  );
  
  describe('handling a request with a valid JWS without type in JWT header', function() {
    var user;
    
    before(function(done) {
      chai.passport.use(strategy)
        .success(function(u) {
          user = u;
          done();
        })
        .req(function(req) {
          // header = { alg: 'RS256' }
          // payload = { iss: 'https://jwt-idp.example.com',
          //   sub: 'mailto:mike@example.com',
          //   aud: 'https://jwt-rp.example.net',
          //   exp: 7702588800 }
          
          req.body = {
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwiZXhwIjo3NzAyNTg4ODAwfQ.KIOxvBb70_PdnesRJNtF37IkaPoCmzA9uC4wQjd2Y2nfh2zDMcuK1B0M2iOCQi8E35xrZH-7EjJJN4NSAUREDyWyNXzMUWTdPTWUjsrvyW1aOHNiYBUojXnf37krg2vS3HksoUtXdmp5cvlCBXW0zp10nXSGSfbWE9HAxKQrsfw'
          };
        })
        .authenticate();
    });
    
    it('should authenticate', function() {
      expect(user).to.be.an('object');
      expect(user.id).to.equal('1234');
      expect(user.issuer).to.equal('https://jwt-idp.example.com');
      expect(user.subject).to.equal('mailto:mike@example.com');
    });
  });
  
  describe('handling a request with an invalid JWS due to missing iss claim', function() {
    var challenge, status;
    
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(c, s) {
          if (typeof c == 'number') {
            s = c;
            c = undefined;
          }
          
          challenge = c;
          status = s;
          done();
        })
        .req(function(req) {
          req.body = {
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwiZXhwIjo3NzAyNTg4ODAwfQ.qHG0DU9Jc8uVC7sAQb6hgCPQYpcW9ltawxhelLEclZTK_hoSTy4vycme4lShOS0MWn_sbvLXbzm8c6DkSsOP3Tq_MzcFHCOAQyUWfqFHN6311-dkaIAzK9DFRlqGSq-shTh9DGx55I4Va4WTPgA0Y5Lf4O3b5GWKzRAtfmNoNIA'
          };
        })
        .authenticate();
    });
    
    it('should fail without challenge', function() {
      expect(challenge).to.be.undefined;
    });
    
    it('should fail without bad request status', function() {
      expect(status).to.equal(400);
    });
  });
  
  describe('handling a request with an invalid JWS due to missing sub claim', function() {
    var challenge, status;
    
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(c, s) {
          if (typeof c == 'number') {
            s = c;
            c = undefined;
          }
          
          challenge = c;
          status = s;
          done();
        })
        .req(function(req) {
          req.body = {
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL2p3dC1ycC5leGFtcGxlLm5ldCIsImV4cCI6NzcwMjU4ODgwMH0.U-Q-x-w2eBfwmLVm1iSCstesgfGUGKI9Ge8aPMnUSx7hvHJVfE3dKl3Yf_3bI5eSA6bFoiTQgylJcRnQngfCxLlJGuIpYThbkCNlWGTCUrY7ZM1eRKECIFxDwdnoHrO1IZrVNkvkQrAGl5-cdveQvTa8LReMzUstX58NYU32Y-0'
          };
        })
        .authenticate();
    });
    
    it('should fail without challenge', function() {
      expect(challenge).to.be.undefined;
    });
    
    it('should fail without bad request status', function() {
      expect(status).to.equal(400);
    });
  });
  
});
