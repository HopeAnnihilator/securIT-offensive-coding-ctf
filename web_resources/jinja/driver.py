from aiohttp import web
import aiohttp_jinja2
import urllib
import cerberus
import logging
from secrets import token_hex
from time import time
from hashlib import sha256
import re
import os
import magic
from base64 import urlsafe_b64encode
import json

logging.basicConfig(
    level = logging.WARNING,
    filename = "/logs/webapp.log",
    format = '%(asctime)s %(message)s',
    datefmt = '%m/%d/%Y %I:%M:%S %p'
)

def setup_routes(app):
    routes = web.RouteTableDef()

    # index page
    @routes.view('/')
    class WebRoot(web.View):
        async def get(self):
            r = await validate_user_cookie(app, self.request)
            context = {
                'index': True,
                'page': 'INDEX'
            }
            return await get_basic_page(r, context, self.request)


    # login api
    @routes.view('/login')
    class WebLogin(web.View):
        async def get(self):
            return web.HTTPFound('/')
        async def post(self):
            context = {
                'index': True,
                'page': 'LOGIN FAILED'
            }
            timeout = await check_timeouts(app, self.request, 'login', 60, 10)
            if not timeout:
                context['msg'] = 'Too many login attempts, please try again in 60 seconds'
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)

            validData = await verify_auth(app, self.request, 'login')
            if validData:
                # if valid verify user password matches password in database
                arr = await verify_creds(app, self.request, validData)
                if arr:
                    resp = web.HTTPFound(arr.pop())
                    user = arr.pop()
                    resp.set_cookie(
                        'AUTH', user['cookie'],
                        domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1], 
                        samesite = "Strict"
                    )
                    resp.set_cookie(
                        'USER', user['user'], 
                        domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1], 
                        samesite = "Strict"
                    )
                    return resp
                else:
                    context['msg'] = 'Failed login attempt, much bad'
                    return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)


    # logout api
    @routes.view('/logout')
    class WebLogout(web.View):
        async def get(self):
            return web.HTTPFound('/')
        async def post(self):
            context = {
                'index': True,
                'page': 'LOGOUT FAILED :P'
            }
            timeout = await check_timeouts(app, self.request, 'logout', 60, 10)
            if not timeout:
                context['msg'] = 'Too many logout attempts, please try again in 60 seconds'
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)

            if ('AUTH' in self.request.cookies) and ('USER' in self.request.cookies):
                resp = web.HTTPFound('/')
                # response.del_cookie('AUTH', domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1])
                # response.del_cookie('USER', domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1])
                resp.set_cookie(
                    name = 'AUTH',
                    value = 'invalid',
                    domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1],
                    path = '/',
                    expires = 'Thu, 01 Jan 1970 00:00:00 GMT',
                    samesite = 'strict'
                )
                resp.set_cookie(
                    name = 'USER', 
                    value = 'invalid', 
                    domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1], 
                    path = '/', 
                    expires = 'Thu, 01 Jan 1970 00:00:00 GMT', 
                    samesite = 'strict'
                )
                return resp
    

    # registration api
    @routes.view('/register')
    class WebLogout(web.View):
        async def get(self):
            return web.HTTPFound('/')
        async def post(self):
            context = {
                'index': True,
                'page': 'REGISTRATION FAILED'
            }
            timeout = await check_timeouts(app, self.request, 'register', 600, 1)
            if not timeout:
                context['msg'] = 'Too many registration attempts, please try again in 600 seconds'
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)

            validData = await verify_auth(app, self.request, 'register')
            if validData:
                if not await app['db'].check_user_exists(validData['user']):
                    data = {}
                    data['user'] = validData['user']
                    data['cookie'] = token_hex(32)
                    data['pass'] = sha256((validData['pass'] + 'UWUSALT').encode()).hexdigest()
                    await app['db'].add_user(validData['user'], data)
                    resp = web.HTTPFound(validData['from'] if validData['from'] else '/')
                    resp.set_cookie(
                        'AUTH', data['cookie'], 
                        domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1],
                        samesite = "Strict"
                    )
                    resp.set_cookie(
                        'USER', data['user'],
                        domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1], 
                        samesite = "Strict"
                    )
                    return resp
                else:
                    context = {
                        'index': True,
                        'msg': 'Failed registration attempt, username taken',
                        'page': 'USERNAME TAKEN'
                    }
                    return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
            else:
                context = {
                    'index': True,
                    'msg': 'Failed registration attempt, much bad, do not use special characters other than _, usernames may be between 4 and 16 characters, and passwords may be between 8 and 32 characters',
                    'page': 'REGISTRATION FAILED'
                }
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)

    # upload page and api
    @routes.view('/upload')
    class WebUpload(web.View):
        async def get(self):
            r = await validate_user_cookie(app, self.request)
            context = {
                'upload': True,
                'page': 'UPLOAD'
            }
            return await get_basic_page(r, context, self.request)
        async def post(self):
            
            timeout = await check_timeouts(app, self.request, 'upload', 600, 10)
            if not timeout:
                context = {
                    'index': True,
                    'page': 'UPLOAD FAILED',
                    'msg' :'Too many upload attempts, please try again in 600 seconds'
                }
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
                
            context = {
                'upload': True
            }
            if self.request.has_body:
                r = await validate_user_cookie(app, self.request)
                match(r):
                    case 'bad cookies' | 'invalid user':
                        context['page']= 'UPLOAD FAILED'
                        return await get_basic_page(r, context, self.request)
                    case 'guest':
                        uploader = 'guest'
                    case _:
                        uploader = r['user']
                
                fileinfo = {'uploader': uploader}
                reader = await self.request.multipart()
                field = await reader.next()

                fieldname = field.name
                filename = field.filename
                
                schema = {
                    'fieldname': {
                        'type': 'string',
                        'required': True,
                        'regex': '^fileupload$'
                    },
                    'filename': {
                        'type': 'string',
                        'required': True,
                        'regex': '^[a-zA-Z0-9\ \._-]+$',
                        'maxlength': 42,
                        'minlength': 4
                    }
                }
                v = cerberus.Validator(schema)
                if v.validate({'fieldname': fieldname, 'filename': filename}):
                    fileinfo['filename'] = filename
                    status = await receive_file_buffered(app, self.request, reader, field, fileinfo)
                    match(status):
                        case 'too long':
                            context['page'] = 'UPLOAD SUCCESS'
                            context['msg'] = 'file description exceeds max of 42 characters and has been truncated but file uploaded successfully'
                        case 'bad description':
                            context['page'] = 'UPLOAD SUCCESS'
                            context['msg'] = 'file description unable to be added but file uploaded successfully'
                        case 'bad filetype':
                            context['page'] = 'UPLOAD FAILED'
                            context['msg'] = 'filetype not allowed and file upload has failed'
                        case 'failed':
                            context['page'] = 'UPLOAD FAILED'
                            context['msg'] = 'file upload failed for an unknown reason, ensure file is not empty and try again'
                        case _:
                            context['page'] = 'UPLOAD SUCCESS'
                            context['msg'] = 'file uploaded successfully'
                    if context['page'] == 'UPLOAD SUCCESS':
                        await app['db'].add_file_user(fileinfo['uploader'].lower(), fileinfo)
                    return await get_basic_page(r, context, self.request)
                else:
                    logging.log(level = 9001, msg = 'File upload attempt failed by ip address: ' + self.request.headers['X-Real-IP'] + " due to invalid filename or upload request: " + field.filename[:128] if field.filename else "")

    # file viewer api
    @routes.view('/files')
    class WebViewer(web.View):
        async def get(self):
            r = await validate_user_cookie(app, self.request)
            context = {
                'viewer': True,
                'page': 'FILES'
            }
            if r not in ['invalid user', 'bad cookies']:
                context['files'] = sorted([i for i in await app['db'].user_files(r['user'] if type(r) is dict else r)], key = lambda i: i['time'], reverse = True)
            return await get_basic_page(r, context, self.request)
            
    # download api
    @routes.view('/download/{file}')
    class WebDownloader(web.View):
        async def get(self):
            context = {
                'index': True,
                'page': 'DOWNLOAD FAILED'
            }
            timeout = await check_timeouts(app, self.request, 'download', 600, 10)
            if not timeout:
                context['msg'] = 'Too many download attempts, please try again in 600 seconds'
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)

            context['msg'] = 'Download attempt failed due to invalid request'
            uid = self.request.match_info['file']
            schema = {
                'uid': {
                    'type': 'string',
                    'required': True,
                    'regex': '^[a-fA-F0-9]+$',
                    'maxlength': 64,
                    'minlength': 64
                }
            }
            v = cerberus.Validator(schema)
            if v.validate({'uid': uid}):
                r = await validate_user_cookie(app, self.request)
                match(r):
                    case 'bad cookies' | 'invalid user':
                        return await get_basic_page(r, context, self.request)
                    case 'guest':
                        user = 'guest'
                    case _:
                        user = r['user']
                fileinfo = await app['db'].get_file_info(user, uid)
                if fileinfo:
                    return web.FileResponse(
                        path = fileinfo['location'], 
                        chunk_size = 8192, 
                        headers = {
                            'Content-Type': fileinfo['type'],
                            'Content-Disposition': "attachment; filename=" + fileinfo['filename']
                        }
                    )
                else:
                    context['msg'] = 'File does not exist or you do not have access to it',
                    return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
            else:
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
                
    setup_static_routes(app)
    return app.add_routes(routes)

def setup_static_routes(app):
    app.router.add_static('/static/', path = 'web_resources/jinja/static', name = 'static')


# ensure user cookie is valid and matches claimed user
async def validate_user_cookie(app, request):
    to_lower = lambda user: user.lower()
    schema = {
        'USER': {
            'type': 'string',
            'maxlength': 16, 
            'minlength': 4, 
            'required': True,
            'coerce': (str, to_lower),
            'regex': '^[\w]+$',
            'forbidden': ['root', 'admin', 'test', 'administrator', 'guest', 'public', 'user']
        }, 
        'AUTH': {
            'type': 'string',
            'required': True,
            'regex': '^[A-Fa-f0-9]+$',
            'maxlength': 64, 
            'minlength': 64, 
        }
    }
    cookies = dict(request.cookies)
    v = cerberus.Validator(schema, purge_unknown = True)
    if v.validate(cookies):
        user = await app['db'].verify_cookie(cookies['AUTH'], cookies['USER'])
        if user:
            return user
        else:
            logging.log(level = 9001, msg = 'Incorrect cookies from ip address: ' + request.headers['X-Real-IP'] + ' Cookies: ' + json.dumps(cookies))
            return 'invalid user'
    elif (len(v.errors) == 2) and (list(v.errors.values()).count(['required field']) == 2):
        return 'guest'
    else:
        logging.log(level = 9001, msg = 'Issue with cookies from ip address: ' + request.headers['X-Real-IP'] + ', Errors: ' + json.dumps(v.errors) + ', Cookies: ' + json.dumps(cookies))
        return 'bad cookies'

# verify user authenticating with proper credentials
async def verify_auth(app, request, method):
    # use parameters in body if found
    if request.has_body:
        data = await parse_request(await request.text(), 3)
        # verify parameters exist
        if not data:
            logging.log(level = 9001, msg = "Bad " + method + " attempt in body from ip address " + request.headers['X-Real-IP'] + ' Body: ' + await request.text())
            return None
    else:
        # use parameters in url
        params = str(request.url).split('?')
        # verify url split properly
        match len(params):
            # if no parameters in request
            case 1:
                logging.log(level = 9001, msg = method + " attempt by " + request.headers['X-Real-IP'] + " missing parameters Submitted URL: " +  str(request.url))
                return None
            # if 1 set of parameters found
            case 2:
                data = await parse_request(params[1], 3)
                # verify parameters exist
                if not data:
                    logging.log(level = 9001, msg = "Bad " + method + " attempt in body from ip address " + request.headers['X-Real-IP'] + ' URL: ' + str(request.url))
                    return None
            # some weird edge case preventer thing
            case _:
                logging.log(level = 9001, msg = "Something weird came in url from ip address " + request.headers['X-Real-IP'] + ' URL: ' + str(request.url))
                return None

    # convert username to lowercase for verification
    to_lower = lambda user: user.lower()
    # set path to / if from invalid location that exists
    to_valid_path = lambda path: '/' if path in ['/login', '/download', '/logout', '/upload', '/register'] else path
    # cerberus validator schema from parameters used in login
    schema = {
        'user': {
            'type': 'string',
            'maxlength': 16, 
            'minlength': 4, 
            'required': True,
            'coerce': (str, to_lower),
            'regex': '^[\w]+$',
            'forbidden': ['root', 'admin', 'test', 'administrator', 'guest', 'public', 'user']
        }, 
        'pass': {
            'type': 'string',
            'required': True,
            'regex': '^[\w]+$',
            'maxlength': 32, 
            'minlength': 8, 
        },
        'from': {
            'type': 'string',
            'required': False,
            'coerce': (str, to_valid_path),
            'allowed': ['/files', '/upload', '/']
        }
    }
    # cerberus validator, removes unknown values
    v = cerberus.Validator(schema, purge_unknown = True)
    # attempt to validate data
    if v.validate(data):
        return data
    # if validation failed
    else:
        logging.log(level = 9001, msg = method + " failed validation requirements from ip address " + request.headers['X-Real-IP'] + " Errors: " + json.dumps(v.errors)  + " Data: " + json.dumps(data))
        return None
        
# parse parameters in request
async def parse_request(params, paramCount):
    try:
        return dict(urllib.parse.parse_qsl(params, max_num_fields = paramCount, strict_parsing = True))
    except ValueError:
        # thrown if parsing fails
        return None

# get a basic web page 
async def get_basic_page(r, context, request):
    match(r):
        case 'bad cookies' | 'invalid user':
            context['msg'] = 'Please Relogin'
            resp = aiohttp_jinja2.render_template('message.html', request = request, context = context)
            resp.set_cookie(name = 'AUTH', value = 'invalid', domain = re.match('.*\/(.*)\/', str(request.url)).group(0)[7:-1], path = '/', expires = 'Thu, 01 Jan 1970 00:00:00 GMT', samesite = 'strict')
            resp.set_cookie(name = 'USER', value = 'invalid', domain = re.match('.*\/(.*)\/', str(request.url)).group(0)[7:-1], path = '/', expires = 'Thu, 01 Jan 1970 00:00:00 GMT', samesite = 'strict')
            # resp.del_cookie('AUTH', domain = re.match('.*\/(.*)\/', str(request.url)).group(0)[7:-1])
            # resp.del_cookie('USER', domain = re.match('.*\/(.*)\/', str(request.url)).group(0)[7:-1])
            return resp
        case 'guest':
            return aiohttp_jinja2.render_template('message.html', request = request, context = context)
        case _:
            context['user'] = r['user']
            return aiohttp_jinja2.render_template('message.html', request = request, context = context)

async def verify_creds(app, request, data):
        user = await app['db'].validate_pass(data['user'], sha256((data['pass'] + 'UWUSALT').encode()).hexdigest())
        # if valid user attempt to return to previous page
        if user:
            return [user, data['from'] if data['from'] else '/']
        # log bad credentials
        else:
            logging.log(level = 9001, msg = "Failed login attempt (bad credentials) by ip address " + request.headers['X-Real-IP'] + " for user " + data['user'])
            return None

async def receive_file_buffered(app, request, reader, field, fileinfo):
    fileinfo['ip'] = request.headers['X-Real-IP']
    fileinfo['time'] = time()
    if not os.path.exists(os.path.join('web_resources', 'files', fileinfo['uploader'].lower())):
        os.mkdir(os.path.join('web_resources', 'files', fileinfo['uploader'].lower()))

    while True:
        uid = token_hex(32)
        if not os.path.exists(os.path.join('web_resources', 'files', fileinfo['uploader'].lower(), uid)):
            fileinfo['location'] = os.path.join('web_resources', 'files', fileinfo['uploader'].lower(), uid)
            fileinfo['uid'] = uid
            break
    
    fileinfo['size'] = 0
    with open(fileinfo['location'], 'wb+') as f:
        while True:
            chunk = await field.read_chunk(size = 8192)
            if not chunk:
                break
            fileinfo['size'] += len(chunk)
            f.write(chunk)

    if fileinfo['size'] < 1 or not os.path.exists(fileinfo['location']):
        logging.log(level = 9001, msg = 'file upload failed due to not existing or size < 0 by: ' + request.headers['X-Real-IP'] + ' for user: ' + fileinfo['uploader']) 
        return 'failed'
    
    fileinfo['type'] = magic.from_buffer(open(fileinfo['location'], 'rb').read(8192), mime = True)
    if not((fileinfo['type'] in ['application/pdf', 'application/json']) or (fileinfo['type'].startswith('text'))):
        logging.log(level = 9001, msg = 'Invalid file type upload attempt failed by ip address: ' + request.headers['X-Real-IP'] + ' filetype: ' + fileinfo['type'])
        try:
            os.remove(fileinfo['location'])
        except FileNotFoundError:
            pass
        return 'bad filetype'

    field = await reader.next()
    if field.name != 'description':
        logging.log(level = 9001, msg = 'missing/bad description for file upload by: ' + request.headers['X-Real-IP'])
        return 'bad description'
        
    description = await field.read_chunk(1024)
    fileinfo['description'] = urlsafe_b64encode(description[:512]).decode()

    if len(description) > 512:
        logging.log(level = 9001, msg = 'description too long when uploading file by: ' + request.headers['X-Real-IP'] + 'description: ' + description.decode())
        return 'too long'


async def check_timeouts(app, request, method, period, maxAttempts):    
    timeout_info = await app['db'].get_timeout_object(request.headers['X-Real-IP'], method)
    try:
        if (time() - timeout_info['time'][1]) > period:
            await app['db'].reset_timeout_object(request.headers['X-Real-IP'], method)
            return True
        else:
            if timeout_info['time'][0] < maxAttempts:
                await app['db'].increment_timeout_counter(request.headers['X-Real-IP'], method, timeout_info)
                if (timeout_info['time'][0] >= maxAttempts) and (maxAttempts > 1):
                    logging.log(level = 9001, msg = "Excessive " + method + " attempts by " + request.headers['X-Real-IP'])
                return True
            else:
                return False
    except TypeError:
        await app['db'].add_new_timeout_object(request.headers['X-Real-IP'], method)
        return True