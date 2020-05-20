const koa = require('koa');
const bodyParser = require('koa-bodyparser');
const session = require('koa-session');

const oauthRouter = require('./routers/oauth-router');
const apiRouter = require('./routers/api-router');

const OAUTH_SERVER_PORT = 3002;

const app = new koa();

app.keys = [ 'some-keys-to-sign-cookies-by-koa-session' ];

app.use(bodyParser());
app.use(session(app));
app.use(async (ctx, next) => {
    //needed by authenticateHandler, see oauth-router
    ctx.request.session = ctx.session;
    await next();
});

app.use(oauthRouter(app, { 'prefix': '/oauth' }).routes());
app.use(apiRouter(app, { prefix: '/api' }).routes());

app.listen(OAUTH_SERVER_PORT, function(){
    console.log(`oauth server listening on port ${OAUTH_SERVER_PORT}`);
});
