/*
 * @Author: chopper
 * @Date: 2020-04-13 20:56:51
 * @LastEditTime: 2020-04-13 21:21:39
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 */

 var req=exports=module.exports={};

 /**
  * @param {User} user
  * @param {Object} options
  * @param {Function} done
  * @api public
  */

  req.login=req.logIn=function(user,options,done){
    if(typeof options==='function'){
      done=options;
      options={};
    }
    options=options||{}
    var property='user'
    if(this._passport&&this._passport.instance){
      property=this._passport.instance._userProperty||'user';
    }
    var session=(options.session===undefined)?true:options.session
    this[property]=user
    if(session){
      if(!this._passport){
        throw new Error('passport.initialize() middleware not in use');
      }
      if(typeof done!=='function'){
        throw new Error('req#login requires a callback function');
      }
      var self=this
      //passport也需要存储一遍session
      this._passport.instance._sm.logIn(this,user,function(err){
        if(err){
          self[property]=null;
          return done(err);
        }
        done();
      });
    }else{
      done&&done();
    }
  }


  /**
   * @description 清理存在的登录的session
   * @api public
   */

  req.logout=req.logOut=function(){
    var property='user';
    if(this._passport&&this._passport.instance){
      property=this._passport.instance._userProperty||'user';
    }
    //req需要把对应的user的字段内容设置为空
    this[property]=null;
    if(this._passport){
      //passport对应的也需要清理掉挂载在上边的user
      this._passport.instance._sm.logOut(this);
    }
  }

  /**
   * @return {Boolean}
   * @api public
   */
  req.isAuthenticated=function(){
    var property='user';
    if(this._passport&&this._passport.instance){
      property=this._passport.instance._userProperty||'user';
    }
    return (this[property])?true:false;
  }

  /**
   * @description 请求是否未进行验证
   * @return {Boolean}
   * @api public
   */
  req.isUnauthenticated=function(){
    return !this.isAuthenticated()
  }

  

 
