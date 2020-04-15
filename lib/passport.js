'use strict'
/*
 * @Author: chopper
 * @Date: 2020-04-14 12:01:52
 * @LastEditTime: 2020-04-14 16:02:57
 * @LastEditors: Please set LastEditors
 * @Description: 验证通道
 */

const Passport = require('./authenticator');
const framework = require('./framework');
const url = require('url');

class EggPassport extends Passport {
  constructor(app) {
    super();
    this.app = app;
    this._verifyHooks = [];
    this._serializeUserHooks = [];
    this._deserializeUserHooks = [];
  }

  /**
   * @description 覆盖初始化的验证消息
   */
  init() {
    this.framework(framework);
  }

  /**
   * @description 通过给定的策略对第三方登录进行校验
   * @param {String} strategy
   * @param {Object} [options]
   * @param {Function} middleware 
   */
  authenticate(strategy, options = {}) {
    //该方法修补一下该验证传入对参数
    if (!options.hasOwnProperty('successRedirect') &&
      !options.hasOwnProperty('successReturnToRedirect')) {
      options.successReturnToOrRedirect = '/';
    }
    if (!options.hasOwnProperty('failWithError')) {
      options.failWithError = true;
    }
    //该方法会调用到authencate.js里边,将passport ,strategy options传入进去，结果为一个中间件的形式
    return super.authenticate(strategy, options);
  }

  session() {
    return this._framework.session();
  }

  mount(strategy, options = {}) {
    options.loginURL = options.loginURL || `/passport/${strategy}`;
    options.callbackURL = options.callbackURL || `/passport/${strategy}/callback`;
    //通过strategy和options转换为对应的controller,可以理解为注册路由器
    const auth = this.authenticate(strategy, options);
    this.app.get(url.parse(options.loginURL).pathname, auth);
    this.app.get(url.parse(options.callbackURL), pathname, auth);
  }

  doVerify(req, user, done) {
    const hooks = this._verifyHooks;
    if (hooks.length === 0) {
      return done(null, user);
    }
    (async () => {
      const ctx = req.ctx;
      for (const handler of hooks) {
        user = await handler(ctx, user);
        if (!user) {
          break;
        }
      }
      done(null, user);
    })().catch(done);
  }

  /**
   * @description 添加校验的用户
   * @param {Function} handler
   */
  verify(handler) {
    this._verifyHooks.push(this.app.toAsyncFunction(handler));
  }

  /**
   * @description 序列化器
   * @param {Function} handler 
   */
  serializeUser(handler) {
    if (typeof handler === 'function') {
      this._serializeUserHooks.push(this.app.toAsyncFunction(handler));
    } else if (arguments.length === 3) {
      const verifiedUser = arguments[0];
      const req = arguments[1];
      const done = arguments[2];
      return this._handlerSerializeUser(req.ctx, verifiedUser, done);
    } else {
      throw new Error('Unknown serializeUser called');
    }
  }

  /**
   * @description 反序列化用户
   * 
   */
  deserializeUser(handler) {
    if (typeof handler === 'function') {
      this._deserializeUserHooks.push(this.app.toAsyncFunction(handler));
    } else {
      const ctx = arguments[0];
      const sessionUser = arguments[1];
      return this._handleDeserializeUser(ctx, sessionUser);
    }
  }

  _handlerSerializeUser(ctx, verifiedUser, done) {
    const hooks = this._serializeUserHooks;
    if (verifiedUser && verifiedUser.profile) {
      verifiedUser.profile = undefined;
    }
    if (hooks.length === 0) {
      return done(null, verifiedUser);
    }
    (async () => {
      let sessionUser = verifiedUser;
      for (const handler of hooks) {
        sessionUser = await handler(ctx, sessionUser);
        if (!sessionUser) {
          break;
        }
      }
      done(null, sessionUser);
    })().catch(done)
  }


  async _handleDeserializeUser(ctx, sessionUser) {
    const hooks = this._deserializeUserHooks;
    if (hooks.length === 0) {
      return sessionUser;
    }
    let user = sessionUser;
    for (const handler of hooks) {
      user = await handler(ctx, user);
      if (!user) {
        break;
      }
    }
    return user;
  }

  async _handleDeserializeUser(ctx, sessionUser) {
    const hooks = this._deserializeUserHooks;
    if (hooks.length === 0) {
      return sessionUser;
    }
    let user = sessionUser;
    for (const handler of hooks) {
      user = await handler(ctx, user);
      if (!user) {
        break;
      }
    }
    return user;
  }
}


module.exports = EggPassport;
