const Router = require('koa-router');
const userDb = require('../db/fake-user-db');

module.exports = ApiRouter;

function ApiRouter(app, options={}){
    options = Object.assign({ prefix: '' }, options);

    var apiRouter = new Router({ prefix: options.prefix }),
        oauth = app.oauth;
    
    apiRouter.get('/user/*', oauth.authenticate({ scope: 'user_info:read' }));
    apiRouter.post('/user/*', oauth.authenticate({ scope: 'user_info:write' }));

    //the error handler, need to set the koa2-oauth-server option 'useErrorHandler' to true, or errors won't be passed along the middleware chain
    apiRouter.all('/*', async (ctx, next) => {
        var oauthState = ctx.state.oauth || {};

        if(oauthState.error){
            //handle the error thrown by the oauth.authenticate middleware here
            ctx.throw(oauthState.error);
            return;
        }

        if(oauthState.token){
            //this means that the access token brought by the request is authenticated
            //for convinience, we put the user associated with the token in ctx.state.user
            ctx.state.user = oauthState.token.user;// => { username: 'the-username' }

            await next();
            return;
        }

        //should not reach here at all
        ctx.throw(new Error('unkown error'));
    });

    /**
     * OAuth Protected API: use to get the user info, in scope 'user_info:read'
     */
    apiRouter.get('/user/detail', async (ctx, next) => {
        var user = ctx.state.user,
            detail = userDb.get(user.username);

        console.log('>>> detail', detail)

        delete detail.password;

        //respond with the user's detail information
        ctx.body = {
            'success': true,
            'result': detail
        };
    });

    /**
     * OAuth Protected API: use to set the user's hobbies, in scope 'user_info:write'
     */
    apiRouter.post('/user/setHobbies', async (ctx, next) => {
        var user = ctx.state.user,
            hobbies = ctx.request.body.hobbies,
            detail = userDb.get(user.username);

        detail.hobbies = hobbies;

        //update hobbies
        userDb.set(user.username, detail);

        ctx.body = {
            'success': true
        };
    });

    return apiRouter;
}