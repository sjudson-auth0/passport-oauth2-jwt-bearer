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
    function(issuer, headers, payload, done) {
      return done(null, { id: '1234', issuer: issuer, subject: payload.sub });
    }
  );
  
  describe('handling a request with a valid JWS with type in JWT header', function() {
    var user;
    
    before(function(done) {
      chai.passport.use(strategy)
        .success(function(u) {
          user = u;
          done();
        })
        .req(function(req) {
          // header = { typ: 'JWT', alg: 'RS256' }
          // payload = { iss: 'https://jwt-idp.example.com',
          //   sub: 'mailto:mike@example.com',
          //   aud: 'https://jwt-rp.example.net',
          //   exp: 7702588800 }
          
          req.body = {
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwiZXhwIjo3NzAyNTg4ODAwfQ.I4PTqSky9yw5DMx8SEQ72JtrEhSo_Ra0wioCNnI3Od1QEQyG0XSyYnEnJJweZIgVyleX7yqXHUnvPQNBvuHwpgguXDqExx91cttEA4LnlCOCG6_dGa_SzrTthKdI5WlPrQ6yDr2PxG0izdnIZVgeeRxKpMQZImnfaZ22EXWnvXA'
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
  
  describe('handling a request with an invalid JWS due to invalid signature', function() {
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
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwiZXhwIjo3NzAyNTg4ODAwfQ.KIOxvBb70_PdnesRJNtF37IkaPoCmzA9uC4wQjd2Y2nfh2zDMcuK1B0M2iOCQi8E35xrZH-7EjJJN4NSAUREDyWyNXzMUWTdPTWUjsrvyW1aOHNiYBUojXnf37krg2vS3HksoUtXdmp5cvlCBXW0zp10nXSGSfbWE9HAxKQrsfX'
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

  describe('handling a request with a sub claim different from the client_id request parameter', function() {
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
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwiZXhwIjo3NzAyNTg4ODAwfQ.KIOxvBb70_PdnesRJNtF37IkaPoCmzA9uC4wQjd2Y2nfh2zDMcuK1B0M2iOCQi8E35xrZH-7EjJJN4NSAUREDyWyNXzMUWTdPTWUjsrvyW1aOHNiYBUojXnf37krg2vS3HksoUtXdmp5cvlCBXW0zp10nXSGSfbWE9HAxKQrsfw',
            'client_id': 'differentclient'
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
  
  describe('handling a request with an invalid JWS due to missing aud claim', function() {
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
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImV4cCI6NzcwMjU4ODgwMH0.SXrKIJ_L71AVgxNsQ_jE81_LzcgIx0UzFLHbvzfyXqNGjsIjMQepsHBgq1H57cjPnIpzPS2pxDhId8mrDHI7FDulRDNZAXI4I9UPYMgXsVhlZlCJ9TfxWP43709gTkM3VenQqfRE6yq7LaqKYpuRGIRZ-vrwVKfZ2EeNzpAU4t0'
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

  describe('handling a request with an aud claim that is not that passed in configuration', function() {
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
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6ImRpZmZlcmVudGF1ZGllbmNlIiwiZXhwIjo3NzAyNTg4ODAwfQ.EzpsldV9Z_VWxlpX3GLgtFIALgoCI8HZ8iB2-4tU-7YQCP02mKnWdqz7bT4Gcafnlq1tzeYahvPbR6lX0DgtjVkQ29PYwegwA2DqmLsB3Ih44Bzu7m7zTgFR1UmoHDKk-CHWuFeVPqx2oWFVC_RGkAzzfkI1jfnwStNd20ydhD0'
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

  describe('handling a request with an invalid JWS due to missing exp claim', function() {
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
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0In0.Nfq-RMvWEqosgBdioUDYhISr9LhQUk3FTtgMifeXP0BOGQ0K1aIp2CRWyfynZP2sw2S73niAJGnMV83u-NG5UwF2eDGRsGIQoK5FYW4R9yPaHEXybQ-VL0aej6T862MCT7-IUtHEi_LC7ui4D9uO-8r8lYxik8GJzJzvYR7qXFA'
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
  
  describe('handling a request with an invalid JWS due to being expired', function() {
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
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwiZXhwIjoxMzkxMjE3NjM2fQ.tYp7i4F8w5JjTmphkAK9GS3YodTnSM4ProPXHFPeOFMA-Yevh15ztWQUEZg_O7iRcgZgR6zJUV1TdVrl8HwVc8ZZ6-xJ60afoK-Qa-F6Xdm6vXxCzlkT_cxRuQRRwT4nJ7oJBWOZLbfEUz99BXHqtUfUmMgA9MXYRwvZWFtbomM'
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
  
  describe('handling a request with an invalid JWS due to not being acceptable before time', function() {
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
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwibmJmIjo3NzAyNTg4ODAwLCJleHAiOjc3MDI2NzUyMDB9.FlmQPYCOV-gxVUXDMLHP_yURaL9EUhNVmpZ8KrpujYtR3oBFTfeMS6xWUImnKjHLsR5Zt1BnIA_CAkLueQRYDV941LKkmbZDqALVMx_jls4lSA8apw1GriPkGCe6aacWeA6mkXknx70g_0zu-1PQK_32pShQei8YXNwjK2aBdJg'
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
  
});
