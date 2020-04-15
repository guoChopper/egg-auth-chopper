/*
 * @Author: chopper
 * @Date: 2020-04-13 21:40:54
 * @LastEditTime: 2020-04-14 16:55:33
 * @LastEditors: Please set LastEditors
 */

 var http=require('http'),
 IncomingMessageExt=require('./request'),
 AuthenticationError=require('./authenticationerror');

 /**
  * @description 中间件
  * @param {Strategy|String|Array} name
  * @param {Object} options
  * @param {Function} callback
  * @return {Function}
  * eg: passport local {
  *   session:false,
  *   successRedirect:undefined
  * }
  * @api public
  */
  module.exports=function authenticate(passport,name,options,callback){
    if(typeof options=='function'){
      callback=options;
      options={};
    }
    options=options||{};
    var multi=true
    if(!Array.isArray(name)){
      name=[name];
      multi=false;
    }
    //其中的next为callback方法,可以提供给前边的调用者判断是否可以进行下一步操作的作用
    return function authenticate(req,res,next){
      if(http.IncomingMessage.prototype.logIn&&
        http.IncomingMessage.prototype.logIn!==IncomingMessageExt.logIn){
          //将logIn方法挂载到原型链上边
          require('./connect').__monkeypatchNode();
      }
      //存储每个策略失败验证的数组
      var failures=[]
      function allFailed(){
        if(callback){
          if(!multi){
            return callback(null,false,failures[0].chalenge,failures[0].status);
          }else{
            var challenges=failures.map(function(f){return f.challenge;});
            var statuses=failures.map(function(f){return f.status;});
            return callback(null,false,challenges,statuses);
          }
        }
        var failure=failures[0]||{},
        challenge=failure.challenge||{},msg;
        if(options.failureFlash){
          var flash=options.failureFlash;
          if(typeof flash==='string'){
            flash={type:'error',message:flash};
          }
          flash.type=flash.type||'error'
          msg=flash.message||challenge.message||challenge;
          if(typeof msg==='string'){
            req.flash(type,msg);
          }
        }
        if(options.failureMessage){
          msg=options.failureMessage;
          if(typeof msg=='boolean'){
            msg=challenge.message||challenge
          }
          if(typeof msg=='string'){
            req.session.messages=req.session.messages||[]
            req.session.messages.push(msg)
          }
        }
        if(options.failureRedirect){
          return res.redirect(options.failureRedirect)
        }
        var rchallenge=[],rstatus,status;
        for(var j=0,len=failures.length;j<len;j++){
          failure=failures[j];
          chalenge=failure.challenge;
          status=failure.status;
          rstatus=rstatus||status;
          if(typeof challenge=='string'){
            rchallenge.push(challenge);
          }
        }
        res.statusCode=rstatus||401;
        if(res.statusCode==401&&rchallenge.length){
          //需要校验的字段
          res.setHeader('WWW-Authenticate',rchallenge);
        }
        //执行错误回调,前提是需要加一个failWithError
        if(options.failWithError){
          //包裹错误信息和错误码
          return next(new AuthenticationError(http.STATUS_CODES[res.statusCode],status));
        }
        res.end(http.STATUS_CODES[res.statusCode])
      }

      (function attemp(i){
        var layer=name[i];
        //如果没有多余的策略
        if(!layer){
          return allFailed();
        }
        var strategy,prototype;
        if(typeof layer.authenticate=='function'){
          strategy=layer;
        }else{
          //通过passport获取到对应到策略
          prototype=passport._strategy(layer);
          //如果没有找到，为非法策略
          if(!prototype){
            return next(new Error('Unknown authentication strategy "'+layer+'"'))
          }
          strategy=Object.create(prototype)
        }

        /**
         * @description 该方法为策略器成功之后的回调,返回用户以及信息
         * @param {Object} user
         * @param {Object} info
         * @api public
         */
        strategy.success=function(user,info){
          if(callback){
            return callback(null,user,info);
          }
          info=info||{};
          var msg;
          //options中是否有successFlash字段,对应的是成功该配置的type名字
          if(options.successFlash){
            var flash=options.successFlash;
            if(typeof flash=='string'){
              flash={type:'success',message:flash};
            }
            flash.type=flash.type||'success';
            var type=flash.type||info.type||'success';
            //成功的信息
            if(typeof msg=='string'){
              req.flash(type,msg);
            }
          }
          //将成功的信息存储到session上边
          if(options.successMessage){
            msg=options.successMessage;
            if(typeof msg=='boolean'){
              msg=info.message||info;
            }
            if(typeof msg=='string'){
              req.session.messages=req.session.messages||[];
              req.session.messages.push(msg);
            }
          }
          //赋予的用户对应的字段
          if(options.assignProperty){
            req[options.assignProperty]=user;
            return next();
          }
          req.logIn(user,options,function(err){
            if(err){
              return next(err);
            }
            function complete(){
              //如果配置了successReturnToOrRedirect会进行成功的跳转
              if(options.successReturnToOrRedirect){
                var url=options.successReturnToOrRedirect;
                if(req.session&&req.session.returnTo){
                  url=req.session.returnTo;
                  delete req.session.returnTo;
                }
                return res.redirect(url)
              }
              next();
            }
            if(options.authInfo!==false){
              passport.transformAuthInfo(info,req,function(err,tinfo){
                if(err){
                  return next(err);
                }
                req.authInfo=tinfo;
                complete();
              });
            }else{
              complete();
            }
          });
        }

        //策略校验错误的时候返回的信息
        strategy.fail=function(challenge,status){
          if(typeof challenge=='number'){
            status=challenge;
            challenge=undefined;
          }
          //将错误信息纪录下来
          failures.push({challenge:challenge,status:status});
          attemp(i+1);
        }

        /**
         * @param {String} url
         * @param {Number} status
         * @api public
         */
        strategy.redirect=function(url,status){
          res.statusCode=status||302;
          res.setHeader('Location',url);
          res.setHeader('Content-Length','0');
          res.end();
        };

        //不需要判断是否成功或失败直接通过
        strategy.pass=function(){
          next();
        };

        strategy.error=function(err){
          //有回调,走一波回调
          if(callback){
            return callback(err);
          }
          //直接将错误的信息报告出去
          next(err);
        }
        //执行策略器的authenticate方法
        strategy.authenticate(req,options);

      })(0);//attempt
    };
  };
