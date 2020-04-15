/*
 * @Author: chopper
 * @Date: 2020-04-13 20:54:13
 * @LastEditTime: 2020-04-14 00:26:50
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 */

var initialize=require('./initialize'),
authenticate=require('./authenticate');

exports=module.exports=function(){
  exports.__monkeypatchNode();
  return {
    initialize:initialize,
    authenticate:authenticate
  };
}

exports.__monkeypatchNode=function(){
  var http=require('http');
  var IncomingMessageExt=require('./request');
  http.IncomingMessage.prototype.login=
  http.IncomingMessage.prototype.logIn=IncomingMessageExt.logIn;
  http.IncomingMessage.prototype.logout=
  http.IncomingMessage.prototype.logOut=IncomingMessageExt.logOut;
  http.IncomingMessage.prototype.isAuthenticated=IncomingMessageExt.isAuthenticated;
  http.IncomingMessage.prototype.isUnauthenticated=IncomingMessageExt.isUnauthenticated;
}