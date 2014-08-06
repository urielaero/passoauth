var   passport = require('passport')
    , passportOAuth = require('passport-oauth')
    , util = require('util');

function Passoauth(configs){
    this._configs = configs;
    this.strategys = [];
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
        if(customStrategy.version == 1)
            strategy = passportOAuth.OAuthStrategy;
        else
            strategy = passportOAuth.OAuth2Strategy;

        strategy.prototype.userProfile = function(accessToken,tokenSecret,params,done){
            var self = this
            , oauth = self._oauth?self._oauth : self._oauth2;
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

        delete customStrategy.profileNormalize;
        delete customStrategy.name;
        delete customStrategy.version;

        passport.use(name,new strategy(customStrategy,function(accessToken,refreshToken,profile,done){
                done(null,profile);
        }));
    });
}

Passoauth.prototype.controller = function(controller,passport_config){
    for(var i in this._configs){
        controller[i] = passport.authenticate(i);
        controller["callback_"+i] = passport.authenticate(i,passport_config);
    /*
    module.exports["callback_"+i] = passport.authenticate(i,{
              successRedirect: '/OAuth/success'
            , failureRedirect: '/OAuth/failed'
            , failureFlash: true
    });
    */
    }
};

function normalizeProfile(profile,done){
    return function(err,body,res){
                if(!err){
                    var json = JSON.parse(body);
                    for(var p in profile.profile){
                        json[p] = json[profile.profile[p]];
                    }
                }

                done(err,json);

    };
}

module.exports = Passoauth;
