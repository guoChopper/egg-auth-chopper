/*
 * @Author: chopper
 * @Date: 2020-04-13 15:45:26
 * @LastEditTime: 2020-04-14 15:18:01
 * @LastEditors: Please set LastEditors
 * @Description: 验证器
 */


function Authenticator(){
  this._key='passport';
  this._strategies={};//策略:本地验证,第三方验证(github,weibo)
  this._serializers=[];//序列化数组
  this._deserializers=[];//反序列化数组
  this._infoTransformers=[];
  this._framework=null;//这个比较关键,使用它进行校验
  this._userProperty='user';//user对应的属性名

  this.init()
}

/**
 * @description 初始化该对象
 * @api protected
 */
Authenticator.prototype.init=function(){
  //初始化一个链接的框架
  this.framework(require('./connect')())
}

/**
 * @description 使用验证器使用策略的方式
 * @param {String|Strategy} name
 * @param {Strategy} strategy
 * @return {Authenticator}
 * @api public
 */
Authenticator.prototype.use=function(name,strategy){
  if(!strategy){
    strategy=name
    name=strategy.name
  }
  //验证器得配备一个名字
  if(!name){
    throw new Error('Authentication strategies must have a name')
  }
  this._strategies[name]=strategy;
  return this;
};

/**
 * @description 删除验证器里边的策略
 * @param {String} name
 * @return {Authenticator} 方便链式调用
 * @api public
 */

 Authenticator.prototype.unuse=function(name){
   delete this._strategies[name];
   return this;
 };

 /**
  * @description 兼容使用该中间件的方法
  * @param {Object} name
  * @return {Authenticator}
  * @api public
  */
 Authenticator.prototype.framework=function(fw){
  this._framework=fw;
  return this;
 };

 /**
  * @description 初始化
  * @param {Object} options
  * @return {Function} middleware
  * @api public
  */
 Authenticator.prototype.initialize=function(options){
   options=options||{};
   this._userProperty=options.userProperty||'user';
   //需要调用到initilize.js里边到插件
   return this._framework.initialize(this,options);
 };

 /**
  * @description 验证方法,结果是一个中间件,可以验证
  * @param {String} strategy
  * @param {Object} options
  * @param {Function} callback
  * @return {Function} middleware
  * @api public
  */

Authenticator.prototype.authenticate=function(strategy,options,callback){
  return this._framework.authenticate(this,strategy,options,callback);
};


/**
 * @description 使用第三方登录时候使用,如果验证成功,
 * 第三方的回调信息会挂载到req的account这个属性上边
 * 使得现有的session和req.user这2个属性对应的内容不会受到影响
 * @param {String} strategy
 * @param {Object} options
 * @return {Function} middleware
 * @api public
 */

Authenticator.prototype.authorize=function(strategy,options,callback){
  options=options||{};
  options.assignProperty='account';
  const fn=this._framework.authorize||this._framework.authenticate;
  return fn(this,strategy,options,callback);
};


/**
 * @description 使用session
 * @param {Object} options
 * @return {Function} middleware
 * @api public
 */
Authenticator.prototype.session=function(options){
  return this.authenticate('session',options)
}


/**
 * @description 将序列化好的用户对象存储到session里边
 * @api public
 */
Authenticator.prototype.serializeUser=function(fn,req,done){
  if(typeof fn==='function'){
    return this._serializers.push(fn);
  }
  var user=fn
  //向后兼容
  if(typeof req==='function'){
    done=req;
    req=undefined;
  }
  //序列化方法链的方式调用
  var stack=this._serializers;
  (function pass(i,err,obj){
    //通过一个'pass'来将报错的程序跳过
    if('pass'===err){
      err=undefined;
    }
    //报错，或已经取得序列化对象结束
    if(err||obj||obj===0){
      return done(err,obj);
    }
    var layer=stack[i]
    if(!layer){
      return done(new Error('Failed to serialize user into session'));
    }
    function serialized(e,o){
      pass(i+1,e,o)
    }
    try{
      var argumentLength=layer.length;
      if(argumentLength==3){
        //里边的user用刀闭包的方式,使得user为全局的对象
        layer(req,user,serialized)
      }else{
        layer(user,serialized)
      }
    }catch(e){
      return done(e);
    }
  })(0)
}

/**
 * @description 反序列化
 * @api public
 */
Authenticator.prototype.deserializeUser=function(fn,req,done){
  if(typeof fn==='function'){
    return this._serializers.push(fn);
  }
  //放序列化一个对象
  var obj=fn
  //将回调方法赋值给done
  if(typeof req==='function'){
    done=req;
    req=undefined;
  }
  //序列化方法链的方式调用
  var stack=this._deserializers;
  (function pass(i,err,user){
    //通过一个'pass'来将报错的程序跳过
    if('pass'===err){
      err=undefined;
    }
    //报错，或已经取得反序列化对象结束
    if(err||user){
      return done(err,user);
    }
    if(user===null||user===false){
      return done(null,false);
    }
    var layer=stack[i]
    if(!layer){
      return done(new Error('Failed to serialize user into session'));
    }
    function serialized(e,o){
      pass(i+1,e,o)
    }
    try{
      var argumentLength=layer.length;
      if(argumentLength==3){
        //里边的user用刀闭包的方式,使得user为全局的对象
        layer(req,obj,serialized)
      }else{
        layer(obj,serialized)
      }
    }catch(e){
      return done(e);
    }
  })(0)
}

/**
 * @description 注册一个方法用来转换验证信息
 * @api public
 */

Authenticator.prototype.transformAuthInfo=function(fn,req,done){
  if(typeof fn==='function'){
    //相当于先存储起来
    return this._infoTransformers.push(fn);
  }

  //通过调用链的方式调用,使用调用链的方式进行对_infoTransformers进行调用
  var info=fn
  //向后兼容
  if(typeof req==='function'){
    done=req;
    req=undefined;
  }
  //序列化方法链的方式调用
  var stack=this._infoTransformers;
  (function pass(i,err,tinfo){
    //通过一个'pass'来将报错的程序跳过
    if('pass'===err){
      err=undefined;
    }
    //报错，或已经取得序列化对象结束
    if(err||tinfo){
      return done(err,tinfo);
    }
    var layer=stack[i]
    if(!layer){
      return done(null,info);
    }
    function transformed(e,o){
      pass(i+1,e,o)
    }
    try{
      var argumentLength=layer.length;
      if(argumentLength==3){
        //里边的user用刀闭包的方式,使得user为全局的对象
        layer(req,info,transformed)
      }else{
        layer(info,transformed)
      }
    }catch(e){
      return done(e);
    }
  })(0)
}


/**
 * @description 通过名字获取策略的名字
 * @param {String} name
 * @return {Strategy}
 * @api private
 */
Authenticator.prototype._strategy=function(name){
  return this._strategies[name];
};


module.exports=Authenticator;





