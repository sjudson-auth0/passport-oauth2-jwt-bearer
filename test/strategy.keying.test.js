var chai = require('chai')
  , fs = require('fs')
  , Strategy = require('../lib/passport-oauth2-jwt-bearer/strategy');


describe('Strategy', function() {
  
  describe('with issue callback that does not provide a key', function() {
    var strategy = new Strategy(
      { audience: 'https://jwt-rp.example.net' },
      function(issuer, done) {
        process.nextTick(function() {
          return done(null, false);
        });
      },
      function(issuer, subject, done) {
        return done(null, { id: '1234', issuer: issuer, subject: subject });
      }
    );
    
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
    
    it('should fail without challenge', function() {
      expect(challenge).to.be.undefined;
    });
    
    it('should fail without status', function() {
      expect(status).to.be.undefined;
    });
  });
  
  describe('with issue callback that encounters an error', function() {
    var strategy = new Strategy(
      { audience: 'https://jwt-rp.example.net' },
      function(issuer, done) {
        process.nextTick(function() {
          return done(new Error('something went wrong'));
        });
      },
      function(issuer, subject, done) {
        return done(null, { id: '1234', issuer: issuer, subject: subject });
      }
    );
    
    var err;
    
    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
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
    
    it('should error', function() {
      expect(err).to.be.an.instanceof(Error);
      expect(err.message).to.equal('something went wrong');
    });
  });
  
  describe('with issue callback that throws an error', function() {
    var strategy = new Strategy(
      { audience: 'https://jwt-rp.example.net' },
      function(issuer, done) {
        throw new Error('something went horribly wrong');
      },
      function(issuer, subject, done) {
        return done(null, { id: '1234', issuer: issuer, subject: subject });
      }
    );
    
    var err;
    
    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
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
    
    it('should error', function() {
      expect(err).to.be.an.instanceof(Error);
      expect(err.message).to.equal('something went horribly wrong');
    });
  });
  
});
