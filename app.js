
'use strict'

const Passport=require('./lib/passport');

module.exports=app=>{
  app.passport=new Passport(app);
  app.config.coreMiddleware.push('passportInitialize');
}