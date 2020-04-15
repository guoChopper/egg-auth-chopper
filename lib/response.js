/*
 * @Author: chopper
 * @Date: 2020-04-14 00:33:26
 * @LastEditTime: 2020-04-14 00:36:29
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 */

 const EventEmitter=require('events');

 class MockResponse extends EventEmitter{
   constructor(ctx){
    super();
    this.ctx=ctx;
   }

   redirect(url){
     this.ctx.redirect(url);
     this.emit('end');
   }

   setHeader(...args){
     this.ctx.set(...args);
   }

   end(content){
     if(content){
      this.ctx.body=content;
      this.emit('end');
     }
   }

   set statusCode(status){
     this.ctx.status=status;
   }

   get statusCode(){
     return this.ctx.status;
   }

 }

 module.exports=MockResponse;