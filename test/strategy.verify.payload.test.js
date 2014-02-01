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
    function(issuer, subject, payload, done) {
      return done(null, { id: '1234', issuer: issuer, subject: subject, member: payload['http://claims.example.com/member'] });
    }
  );
  
  describe('handling a request with a valid JWS with additional members in JWT payload', function() {
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
          //   exp: 7702588800,
          //   "http://claims.example.com/member": true }
          
          req.body = {
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwiZXhwIjo3NzAyNTg4ODAwLCJodHRwOi8vY2xhaW1zLmV4YW1wbGUuY29tL21lbWJlciI6dHJ1ZX0.VRYCuXOLudUZxz6H8u8rM5qQvgDOAmffOO-QY8DWOO3Mg_WvVEPbNndl8KXjPwJiBOmqwLhPAk9-Y-z8SrwVT3ln8cSmNekMDb4Fkw8FyBI6vUBh-83N-IZQrMpQaNvv7_L8srUvYR2Rx3OmQjmBcJEda_iZaLRXxSxuVOHN9lw'
          };
        })
        .authenticate();
    });
    
    it('should authenticate', function() {
      expect(user).to.be.an('object');
      expect(user.id).to.equal('1234');
      expect(user.issuer).to.equal('https://jwt-idp.example.com');
      expect(user.subject).to.equal('mailto:mike@example.com');
      expect(user.member).to.be.true;
    });
  });
  
});
