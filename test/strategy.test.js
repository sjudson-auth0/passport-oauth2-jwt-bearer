var Strategy = require('../lib/passport-oauth2-jwt-bearer/strategy');


describe('Strategy', function() {
    
  var strategy = new Strategy({ audience: 'http://www.example.com/' }, function(){}, function(){});
    
  it('should be named oauth2-jwt-bearer', function() {
    expect(strategy.name).to.equal('oauth2-jwt-bearer');
  });
  
  it('should throw if constructed without an audience option and without skipAudienceCheck', function() {
    expect(function() {
      new Strategy(function(){}, function(){});
    }).to.throw(TypeError, 'OAuth 2.0 JWT bearer strategy requires an audience option');
  });

  it('should not throw if constructed without an audience option but with skipAudienceCheck', function() {
    expect(function() {
      new Strategy({ skipAudienceCheck: true }, function(){}, function(){});
    }).to.not.throw(TypeError, 'OAuth 2.0 JWT bearer strategy requires an audience option');
  });
  
  it('should throw if constructed without a keying callback', function() {
    expect(function() {
      new Strategy({ audience: 'http://www.example.com/' });
    }).to.throw(TypeError, 'OAuth 2.0 JWT bearer strategy requires a keying callback');
  });
  
  it('should throw if constructed without a verify callback', function() {
    expect(function() {
      new Strategy({ audience: 'http://www.example.com/' }, function(){});
    }).to.throw(TypeError, 'OAuth 2.0 JWT bearer strategy requires a verify callback');
  });
  
});
