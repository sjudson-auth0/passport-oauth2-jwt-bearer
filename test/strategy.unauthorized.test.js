var chai = require('chai')
  , Strategy = require('../lib/passport-oauth2-jwt-bearer/strategy');


describe('Strategy', function() {
  
  var strategy = new Strategy(
    function() {},
    function() {}
  );
  
  describe('handling a request without a parsed body', function() {
    var challenge, status;
    
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(c, s) {
          challenge = c;
          status = s;
          done();
        })
        .req(function(req) {
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
  
  describe('handling a request without an assertion', function() {
    var challenge, status;
    
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(c, s) {
          challenge = c;
          status = s;
          done();
        })
        .req(function(req) {
          req.body = {
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
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
  
  describe('handling a request without an assertion type', function() {
    var challenge, status;
    
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(c, s) {
          challenge = c;
          status = s;
          done();
        })
        .req(function(req) {
          req.body = {
            'client_assertion': 'eyJhbGciOiJyczI1NiJ9.eyJpc3MiOiJodHRwOi8vd3d3LmV4YW1wbGUuY29tLyIsInNvZnR3YXJlX2lkIjoiMTIzNCJ9.M-ZPqGU2J7XSkstGfyRc9Nbt9wamlohDQbIbfX5zVlGQjojPZWfFywPdjr64FQGzxC5bqwBXX8VyvKcXbuFlC-2AMJIu8nxpzV-_mJ6ewynGVQQ8NRCsa9pnqLBeXv22XQzF9XOn1uOAUfQsNafnQeuTkZraUyvhrJ9znNdWfwM'
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
  
  describe('handling a request with a non-JWT assertion type', function() {
    var challenge, status;
    
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(c, s) {
          challenge = c;
          status = s;
          done();
        })
        .req(function(req) {
          req.body = {
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:foo-bearer',
            'client_assertion': 'eyJhbGciOiJyczI1NiJ9.eyJpc3MiOiJodHRwOi8vd3d3LmV4YW1wbGUuY29tLyIsInNvZnR3YXJlX2lkIjoiMTIzNCJ9.M-ZPqGU2J7XSkstGfyRc9Nbt9wamlohDQbIbfX5zVlGQjojPZWfFywPdjr64FQGzxC5bqwBXX8VyvKcXbuFlC-2AMJIu8nxpzV-_mJ6ewynGVQQ8NRCsa9pnqLBeXv22XQzF9XOn1uOAUfQsNafnQeuTkZraUyvhrJ9znNdWfwM'
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
