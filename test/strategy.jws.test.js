var chai = require('chai')
  , fs = require('fs')
  , Strategy = require('../lib/passport-oauth2-jwt-bearer/strategy');


describe('Strategy', function() {
  
  var strategy = new Strategy(
    function(issuer, done) {
      if (issuer != 'https://jwt-idp.example.com') { return done('unexpected issuer'); }
      return fs.readFile(__dirname + '/keys/rsa/cert.pem', 'utf8', done);
    },
    function(subject, done) {
      return done(null, { id: '1234', subject: subject });
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
      expect(user.subject).to.equal('mailto:mike@example.com');
    });
  });
  
});
