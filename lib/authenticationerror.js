/*
 * @Author: chopper
 * @Date: 2020-04-14 11:52:23
 * @LastEditTime: 2020-04-14 11:54:39
 * @LastEditors: Please set LastEditors
 * @Description: 校验失败的
 */

/**
 * @description 校验失败的
 * @api private
 */

 function AuthenticationError(message,status){
  Error.call(this);
  Error.captureStackTrace(this,arguments.callee);
  this.name='AuthenticationError';
  this.message=message;
  this.status=status||401;
 }

 AuthenticationError.prototype.__proto__=Error.prototype;

 module.exports=AuthenticationError;
