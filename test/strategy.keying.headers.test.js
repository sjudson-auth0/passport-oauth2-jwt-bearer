var chai = require('chai')
  , fs = require('fs')
  , Strategy = require('../lib/passport-oauth2-jwt-bearer/strategy');


describe('Strategy', function() {
  
  var strategy = new Strategy(
    { audience: 'https://jwt-rp.example.net' },
    function(issuer, headers, done) {
      if (issuer != 'https://jwt-idp.example.com') { return done('unexpected issuer'); }
      if (headers.jku != 'https://jwt-idp.example.com/jwks.json') { return done('unexpected jku header'); }
      if (headers.kid != '20140131') { return done('unexpected kid header'); }
      return fs.readFile(__dirname + '/keys/rsa/cert.pem', 'utf8', done);
    },
    function(issuer, subject, done) {
      return done(null, { id: '1234', issuer: issuer, subject: subject });
    }
  );
  
  describe('handling a request with a valid JWS with additional members in JWT header', function() {
    var user;
    
    before(function(done) {
      chai.passport.use(strategy)
        .success(function(u) {
          user = u;
          done();
        })
        .req(function(req) {
          // header = { alg: 'RS256', jku: 'https://jwt-idp.example.com/jwks.json', kid: '20140131' }
          // payload = { iss: 'https://jwt-idp.example.com',
          //   sub: 'mailto:mike@example.com',
          //   aud: 'https://jwt-rp.example.net',
          //   exp: 7702588800 }
          
          req.body = {
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': 'eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vand0LWlkcC5leGFtcGxlLmNvbS9qd2tzLmpzb24iLCJraWQiOiIyMDE0MDEzMSJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwiZXhwIjo3NzAyNTg4ODAwfQ.qtWfoA9DBPN-Y8QZXH11t6GGg81bTaq2YP7Z4Hod02Llo_BhINEs_Fi9Zvh7EATmi4KH2TA5RYp8xts3BdPS_JLNzGUNFdp9BAlgUlEqZNn65UFidU4oml3EuaakhzChtteG2k18GJ9TzkHOZ2PugVnw3DV7iylthPse-R3wON8'
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
  
});
