/*
 * @Author: chopper
 * @Date: 2020-04-13 17:49:12
 * @LastEditTime: 2020-04-14 19:27:44
 * @LastEditors: Please set LastEditors
 * @Description: 校验使用的framework
 */
const connectFramework=require('./connect')();
const MockResponse=require('./response');

 /**
  * 兼容framework
  */
 module.exports={
  initialize,
  session,
  authenticate,
 }

 //这个才是真正运用在egg上边的插件
 function initialize(passport){ //Authenticator对象
  //该插件的作用是将ctx的session挂载到req上边
   return function passportInitialize(ctx,next){
    const req=ctx.req;
    req._passport={
      instance:passport,
    }
    //挂载ctx
    req.ctx=ctx;
    req.session=ctx.session;
    req.query=ctx.query;
    req.body=ctx.request.body;
    if(req.session&&req.session[passport._key]){
      req._passport.session=req.session[passport._key];
    }
    return next();
  }
 }

 function session(){
   return async function passportSession(ctx,next){
      const req=ctx.req;
      let sessionUser;
      if(req._passport.session){
        sessionUser=req._passport.session.user;
      }
      if(sessionUser||sessionUser===0){
        const user=await ctx.app.passport.deserializeUser(ctx,sessionUser);
        if(!user){
          req._passport.session.user=undefined;
        }else{
          req[ctx.app.passport._userProperty]=user;
        }
      }
      return next();
   }
 }

 function authenticate(passport,name,options){
  const connectMiddleware=connectFramework.authenticate(passport,name,options);
  //中间件
  return async function passportAuthenticate(ctx,next){
    //将req,res分解出来，可以在使用到该验证插件的时候进行传参使用
    const req=ctx.req;
    //对res进行二次包装，赋予其成为一个触发器
    const res=new MockResponse(ctx);

    //使用connectMiddleware的方式
    let resEnd=false;
    await new Promise((resolve,reject)=>{
      res.once('end',()=>{
        resEnd=true;
        resolve();
      });
      //验证主要执行该验证中间件
      connectMiddleware(req,res,err=>{
        if(err)return reject(err);
        resolve();
      });
    });
    //response end
    if(resEnd)return;
    return next();
  }
 }