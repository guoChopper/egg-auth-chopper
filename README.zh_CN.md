# 注册方式 config/plugin.js
exports.authChopper={
	enable:true,
	package:'egg-auth-chopper'
}

# 使用方式
# 挂载校验器到passport上边
function installPassport(passport,{verify}){
	passport.verify(verify)
}

# 下面的方法对应为校验器
async (ctx,{username,password})=>{
	const email=username
	await ctx.verify('user.signin','body')
	//通过model的Auth方法进行校验
	const user=await ctx.model.User.Auth(email,password)
	// ctx.assert(user,400,'用户或密码错误')
	if(!user){
		ctx.throw(400,'用户或密码错误')
	}
	const raw_user=R.omit(['password','created_at','updated_at'],user.toJSON())
	//这个是通过json-web-token 生成的token,可以在到时候对该token进行验证的时候可以获取到指定到信息
	const token=await ctx.sign_token(raw_user,ctx.request.body.remember_me)
	ctx.body=token
	return token
}

# 初始化一个策略器,目的是提取传输进来的用户信息,将策略器注册到eggPassport 上边,eggPassport的基类为Authenticator.js，doVerify的校验在上边的方法中进行,可以细看下边的 LocalStrategy
# 使用方式 initLocalStrategy(app)
async initLocalStrategy(app){
const config={
  usernameField:"email",
  passwordField:"password",
  passReqToCallback:true
}
# 校验时使用,LocalStrategy的作用是提取用户信息
app.passport.use(new LocalStrategy(config,(req,username,password,done)=>{
  const user={
    provider:'local',
    username,
    password
  }
  app.passport.doVerify(req,user,done)
}))
}

# 将校验器注册到passport上边，以便提供给后续调用authenticate方法使用 
# @param {Array} keys
# @param {Passport} passport ,Passport从passport.js文件定义的EggPassport上边定义
# @param {Controller} controller 为egg.Controller
# 调用方式 mountPassportToController(['local'],app.passport,controller) 将local的验证实例绑定到controller上边，该方法从passport实例上边获取 -> 结果为 Controller.passport.local=(ctx,next)=>{} 这种形式
function mountPassportToController(keys,passport,controller){
	if(!controller.passport){
		controller.passport={}
	}
	forEach(value=>{
		if(DEV){
			console.log(`${chalk.blue('[mount passport]')} ${chalk.red(value)}`)
		}
		controller.passport[value]=passport.authenticate(value,{
			session:false,
			successRedirect:undefined
		})
	},keys)
}



# 策略器基类base.js

class Strategy{
	 constructor(){
	 }

	 authenticate(req,options){
		throw new Error('Strategy#you should have a subclass to override me( current method authenticate)');
	 };
 }

 module.exports=Strategy;

# 创建出来的一个自定义策略器

 const BaseStrategy = require('./base');


class LocalStrategy extends BaseStrategy {
	//需要传入一个回调函数
	constructor(options, verify) {
		super();
		if (typeof options === 'function') {
			verify = options;
			options = {}
		}
		if (!verify) {
			throw new TypeError('LocalStrategy reqires a verify callback');
		}
		this._usernameField = options.usernameField || 'username';
		this._passwordField = options.passwordField || 'password';
		this.name = 'local';
		this._verify = verify;
		this._passReqToCallback = options.passReqToCallback;
	}

	authenticate(req,options){
		options=options||{};
		const lookup=this.lookup;
		var username=lookup(req.body,this._usernameField||lookup(req.query,this._usernameField))
		var password=lookup(req.body,this._passwordField||lookup(req.query,this._passwordField))
		if(!username||!password){
			return this.fail({message:options.badRequestMessage||'Missing credentials'},400);
		}
		const verified=(err,user,info)=>{
			if(err){
				return this.error(err);
			}
			if(!user){
				return this.fail(info);
			}
			this.success(user,info);
		}
		try{
			//通过req添加一个成功的回到
			if(this._passReqToCallback){
				//加一个成功的回调
				this._verify(req,username,password,verified);
			}else{
				this._verify(username,password,verified);
			}
		}catch(err){
			return this.error(err);
		}
	}

	//查找对应的校验字段
	lookup(obj,field){
		if(!obj){
			return null;
		}
		var chain = field.split(']').join('').split('[');
		for (var i = 0, len = chain.length; i < len; i++) {
			var prop = obj[chain[i]];
			if (typeof(prop) === 'undefined') { return null; }
			if (typeof(prop) !== 'object') { return prop; }
			obj = prop;
		}
		return null;
	}

}


module.exports=LocalStrategy;