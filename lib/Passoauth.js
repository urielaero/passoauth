var   passport = require('passport')
    , passportOAuth = require('passport-oauth')
    , util = require('util');

function Passoauth(configs){
    this._configs = configs;
    this.strategys = [];
    this.passport = passport;
}

Passoauth.prototype.init = function(){
    var self = this;
    for(var name in self._configs){
        var obj =  self._configs[name];
        obj.name = name;
        self.strategys.push(obj);
    };
}

Passoauth.prototype.configure = function(){
    this.init();
    this.strategys.forEach(function(customStrategy){
        var name = customStrategy.name
        , profile = customStrategy.profileNormalize
        , strategy;

        var st = new Strategy(customStrategy,function(accessToken,refreshToken,profile,done){
                done(null,profile);
        });


        delete customStrategy.profileNormalize;
        delete customStrategy.name;
        delete customStrategy.version;



        passport.use(name,st);
    });
}

Passoauth.prototype.controller = function(controller,passport_config){
    for(var i in this._configs){
        controller[i] = passport.authenticate(i);
        controller["callback_"+i] = passport.authenticate(i,passport_config);
    }
};

function normalizeProfile(profile,done){
    return function(err,body,res){
                if(!err){
                    var json = JSON.parse(body);
                    for(var p in profile.profile){
                        var keys = profile.profile[p].split('.')
                        , j = json;
                        for(var k=0;k<keys.length;k++){
                            j = j[keys[k]]
                        }
                        json[p] = j;
                        if(keys.length > 0 && keys[0]!=p)
                            delete json[keys[0]];
                    }
                }
                if(profile.callback)
                    profile.callback(err,json,done);
                done(err,json);
    };
}


function Strategy(options,verify){
    this.idName = options.name;
    this.profile = options.profileNormalize;
    passportOAuth.OAuth2Strategy.call(this,options,verify);
}

util.inherits(Strategy,passportOAuth.OAuth2Strategy);

Strategy.prototype.userProfile = function(accessToken,tokenSecret,params,done){
    var self = this
    , oauth = self._oauth?self._oauth : self._oauth2
    , profile = self.profile;
    if(profile){
        var length = profile.params && profile.params.length || 0
        , url = [profile.url]
        , functionTmp;
        for(var p=0;p<length;p++){
            url = url.concat(params[profile.params[p]]);
        }

        url = util.format.apply(null,url);
        if(typeof tokenSecret == 'function'){
            done = tokenSecret;
            tokenSecret = null;
        }

        functionTmp = normalizeProfile(profile,done);
        oauth.get(url,accessToken,tokenSecret || functionTmp,functionTmp);
    }
};

module.exports = Passoauth;
