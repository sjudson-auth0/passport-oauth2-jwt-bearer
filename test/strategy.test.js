var Strategy = require('../lib/passport-oauth2-jwt-bearer/strategy');


describe('Strategy', function() {
    
  var strategy = new Strategy(function(){}, function(){});
    
  it('should be named oauth2-jwt-bearer', function() {
    expect(strategy.name).to.equal('oauth2-jwt-bearer');
  });
  
  it('should throw if constructed without a keying callback', function() {
    expect(function() {
      new Strategy();
    }).to.throw(TypeError, 'OAuth 2.0 JWT bearer strategy requires a keying callback');
  });
  
  it('should throw if constructed without a verify callback', function() {
    expect(function() {
      new Strategy(function(){});
    }).to.throw(TypeError, 'OAuth 2.0 JWT bearer strategy requires a verify callback');
  });
  
});
