/*
 * @Author: chopper
 * @Date: 2020-04-14 00:22:26
 * @LastEditTime: 2020-04-14 00:24:38
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 */

 module.exports=function(passport){
   return function initialize(req,res,next){
    req._passport={};
    req._passport.instance=passport
    if(req.session&&req.session[passport._key]){
      //如果存在session数据
      req._passport.session=req.session[passport._key];
    }
    next();
   }
 }