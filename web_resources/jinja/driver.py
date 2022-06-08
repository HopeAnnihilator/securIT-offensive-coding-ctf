from aiohttp import web
import aiohttp_jinja2
import urllib
import cerberus
from string import ascii_letters, digits
import logging
from secrets import token_hex
from time import time
import asyncio
from hashlib import sha256
import re
import os
import magic
from base64 import urlsafe_b64encode
import numpy as np
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
            arr = await(verify_auth(app, self.request))
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
                context = {
                    'index': True,
                    'msg': 'Failed login attempt, much bad',
                    'page': 'LOGIN FAILED'
                }
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)


    # logout api
    @routes.view('/logout')
    class WebLogout(web.View):
        async def get(self):
            return web.HTTPFound('/')
        async def post(self):
            if ('AUTH' in self.request.cookies) and ('USER' in self.request.cookies):
                response = web.HTTPFound('/')
                response.del_cookie('AUTH', domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1])
                response.del_cookie('USER', domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1])
                return response
    

    # registration api
    @routes.view('/register')
    class WebLogout(web.View):
        async def get(self):
            return web.HTTPFound('/')
        async def post(self):
            if self.request.has_body:
                check = await check_timeouts(app, self.request.headers['X-Real-IP'], ['register'])
                if check:
                    return aiohttp_jinja2.render_template('message.html', request = self.request, context = check)
                await app['db'].log_request(self.request.headers['X-Real-IP'], {'time': time(), 'action': 'register'})
                
                try:
                    data = dict(urllib.parse.parse_qsl(await self.request.text(), max_num_fields = 2, strict_parsing = True))
                except ValueError:
                    logging.log(level = 9001, msg = "Attack Detected at /register: " + await self.request.text())
                    return web.Response(text = "Nope", status = 500)
                schemaAuth = {
                    'user': {'type': 'string', 'maxlength': 16, 'minlength': 4, 'forbidden': ['root', 'admin', 'test', 'administrator', 'guest']}, 
                    'pass': {'type': 'string', 'maxlength': 32, 'minlength': 4}
                }
                user = data['user'].lower()
                v = cerberus.Validator(schemaAuth)
                if v.validate(data) and \
                not set(data['pass']).difference(ascii_letters + digits) and \
                not set(user).difference(ascii_letters + digits):
                    if not await app['db'].check_user_exists(data['user']):
                        data['cookie'] = token_hex(32)
                        data['pass'] = sha256((data['pass'] + 'UWUSALT').encode()).hexdigest()
                        await app['db'].add_user(data['user'], data)
                        await app['db'].add_timeout(self.request.headers['X-Real-IP'], time() + 600, "registration")
                        response = web.HTTPFound('/')
                        response.set_cookie('AUTH', data['cookie'], domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1], samesite = "Strict")
                        response.set_cookie('USER', data['user'], domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1], samesite = "Strict")
                        return response
                    else:
                        context = {
                            'msg': 'username taken',
                            'page': 'FAILED'
                        }
                        return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
                else:
                    context = {
                        'msg': 'oops, you messed up :P',
                        'page': 'FAILED'
                    }
                    return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
            else:
                context = {
                    'msg': 'please wait at least 5 mins to create another user',
                    'page': 'TIMEOUT'
                }
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)


    # upload page and api
    @routes.view('/upload')
    class WebUpload(web.View):
        @aiohttp_jinja2.template('upload.html')
        async def get(self):
            if ('AUTH' in self.request.cookies) and ('USER' in self.request.cookies):
                cookies = dict(self.request.cookies)
                cookies['USER'] = cookies['USER'].lower()
                schema = {
                    'USER': {'type': 'string','maxlength': 16, 'minlength': 4, 'forbidden': ['root', 'admin', 'test', 'administrator', 'guest']}, 
                    'AUTH': {'type': 'string', 'maxlength': 64, 'minlength': 64}
                }
                v = cerberus.Validator(schema)
                if v.validate(cookies) and \
                    not set(cookies['AUTH']).difference(ascii_letters + digits) and \
                    not set(cookies['USER']).difference(ascii_letters + digits):
                    if await app['db'].verify_cookie(cookies['AUTH'], cookies['USER']):
                        return {
                            'user': cookies['USER'],
                            'page': 'UPLOAD FILE'
                        }

        async def post(self):
            check = await check_timeouts(app, self.request.headers['X-Real-IP'], ['upload'])
            if check:
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = check)
            await app['db'].log_request(self.request.headers['X-Real-IP'], {'time': time(), 'action': 'upload'})

            fileinfo = {}

            reader = await self.request.multipart()
            field = await reader.next()
            
            # verify field name correct and filename exists
            if field.name != 'fileupload' or not field.filename:
                await app['db'].add_timeout(self.request.headers['X-Real-IP'], time() + 30, 'upload')
                context = {
                    'msg': 'SUS',
                    'page': 'SUS'
                }
                logging.log(level = 9001, msg = 'File upload attempt failed by ip address: ' + self.request.headers['X-Real-IP'] + " due to bad request parameters")
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
            
            # verify valid filename 
            if set(field.filename).difference(ascii_letters + digits + '.') or field.filename.startswith('.') or (len(field.filename) > 256):
                await app['db'].add_timeout(self.request.headers['X-Real-IP'], time() + 60, 'upload')
                context = {
                    'msg': 'File Upload failed, filename may only contain A-Z, a-z, 0-9, and "." filename may also not be longer than 256 characters',
                    'page': 'FAILED'
                }
                logging.log(level = 9001, msg = 'File upload attempt failed by ip address: ' + self.request.headers['X-Real-IP'] + " due to invalid filename: " + field.filename[:512])
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)

            # verify user logged in
            if ('AUTH' in self.request.cookies) and ('USER' in self.request.cookies):
                cookies = dict(self.request.cookies)
                cookies['USER'] = cookies['USER'].lower()
                schema = {
                    'USER': {'type': 'string','maxlength': 16, 'minlength': 4, 'forbidden': ['root', 'admin', 'test', 'administrator', 'guest']}, 
                    'AUTH': {'type': 'string', 'maxlength': 64, 'minlength': 64}
                }
                v = cerberus.Validator(schema)
                if v.validate(cookies) and \
                    not set(cookies['AUTH']).difference(ascii_letters + digits) and \
                    not set(cookies['USER']).difference(ascii_letters + digits):
                    if await app['db'].verify_cookie(cookies['AUTH'], cookies['USER']):
                        fileinfo['owner'] = cookies['USER']
                    else:
                        fileinfo['owner'] = "Guest"
                else:
                    fileinfo['owner'] = "Guest"
            else:
                fileinfo['owner'] = "Guest"

            fileinfo['filename'] = field.filename
            if not os.path.exists(os.path.join('web_resources', 'files', fileinfo['owner'].lower())):
                os.mkdir(os.path.join('web_resources', 'files', fileinfo['owner'].lower()))

            while True:
                randomFilename = token_hex(32)
                if not os.path.exists(os.path.join('web_resources', 'files', fileinfo['owner'].lower(), randomFilename)):
                    fileinfo['location'] = os.path.join('web_resources', 'files', fileinfo['owner'].lower(), randomFilename)
                    fileinfo['uid'] = randomFilename
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
                await app['db'].add_timeout(self.request.headers['X-Real-IP'], time() + 60, 'upload')
                context = {
                    'msg': 'File Upload failed....',
                    'page': 'FAILED'
                }
                try:
                    os.remove(fileinfo['location'])
                except FileNotFoundError:
                    pass
                logging.log(level = 9001, msg = 'File upload attempt failed by ip address: ' + self.request.headers['X-Real-IP'])
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
            
            fileinfo['type'] = magic.from_buffer(open(fileinfo['location'], 'rb').read(8192), mime = True)
            if not((fileinfo['type'] in ['application/pdf', 'application/json']) or (fileinfo['type'].startswith('text'))):
                await app['db'].add_timeout(self.request.headers['X-Real-IP'], time() + 300, 'upload')
                logging.log(level = 9001, msg = 'Invalid file type upload attempt failed by ip address: ' + self.request.headers['X-Real-IP'] + ' filetype: ' + fileinfo['type'])
                try:
                    os.remove(fileinfo['location'])
                except FileNotFoundError:
                    pass
                context = {
                    'msg': 'Filetype not allowed',
                    'page': 'FAILED'
                }
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)


            field = await reader.next()
            if field.name != 'description':
                await app['db'].add_timeout(self.request.headers['X-Real-IP'], time() + 60, 'upload')
                try:
                    os.remove(fileinfo['location'])
                except FileNotFoundError:
                    pass
                context = {
                    'msg': 'Invalid field name',
                    'page': 'FAILED'
                }
                logging.log(level = 9001, msg = 'Invalid parameters by ip address: ' + self.request.headers['X-Real-IP'])
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)

            description = await field.read_chunk(513)
            fileinfo['description'] = urlsafe_b64encode(description[:512]).decode()
            fileinfo['ip'] = self.request.headers['X-Real-IP']
            fileinfo['time'] = time()

            await app['db'].add_file_user(cookies['AUTH'] if fileinfo['owner'] else None, fileinfo['owner'], fileinfo)
            if len(description) > 512:
                context = {
                    'msg': 'File Description exceeds max length of 512 characters and will be truncated',
                    'page': 'FAILED'
                }
                logging.log(level = 9001, msg = 'Overly long file description sent by ip address: ' + self.request.headers['X-Real-IP'] + ' truncated description: ' + fileinfo['description'])
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
            else:
                context = {
                    'msg': 'File uploaded successfully',
                    'page': 'INDEX'
                }
                logging.log(level = 9001, msg = 'File uploaded successfully by ip address: ' + self.request.headers['X-Real-IP'])
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = context)


    # login api
    @routes.view('/files')
    class WebViewer(web.View):
        #@aiohttp_jinja2.template('viewer.html')
        async def get(self):
            r = await validate_user_cookie(app, self.request)
            context = {
                'viewer': True,
                'page': 'FILES'
            }
            return await get_basic_page(r, context, self.request)
            # match(r):
            #     case 'bad cookies' | 'invalid user':
            #         context = {
            #             'viewer': True,
            #             'msg': 'Please relogin, displaying only public files',
            #             'page': 'FILES'
            #         }
            #         resp = aiohttp_jinja2.render_template('message.html', request = self.request, context = context)
            #         resp.set_cookie(name = 'AUTH', value = 'invalid', path = '/', expires = 'Thu, 01 Jan 1970 00:00:00 GMT', samesite = 'strict')
            #         resp.set_cookie(name = 'USER', value = 'invalid', path = '/', expires = 'Thu, 01 Jan 1970 00:00:00 GMT', samesite = 'strict')
            #         resp.del_cookie('AUTH', domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1])
            #         resp.del_cookie('USER', domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1])
            #         return resp
            #     case 'guest':
            #         context = {
            #             'viewer': True,
            #             'page': 'FILES'
            #         }
            #         return aiohttp_jinja2.render_template('viewer.html', request = self.request, context = context)
            #     case _:
            #         context = {
            #             'viewer': True,
            #             'page': 'FILES',
            #             'user': r['user']
            #         }
            #         return aiohttp_jinja2.render_template('viewer.html', request = self.request, context = context)

            # print(dict(self.request.cookies), flush = True)
            # if ('AUTH' in self.request.cookies) and ('USER' in self.request.cookies):
            #     cookies = dict(self.request.cookies)
            #     cookies['USER'] = cookies['USER'].lower()
            #     schema = {
            #         'USER': {'type': 'string','maxlength': 16, 'minlength': 4, 'forbidden': ['root', 'admin', 'test', 'administrator', 'guest']}, 
            #         'AUTH': {'type': 'string', 'maxlength': 64, 'minlength': 64}
            #     }
            #     v = cerberus.Validator(schema)
            #     if v.validate(cookies) and \
            #         not set(cookies['AUTH']).difference(ascii_letters + digits) and \
            #         not set(cookies['USER']).difference(ascii_letters + digits):
            #         if await app['db'].verify_cookie(cookies['AUTH'], cookies['USER']):
            #             return {
            #                 'user': cookies['USER'],
            #                 'page': 'FILES',
            #                 'files': await app['db'].user_files(cookies['AUTH'], cookies['USER'])
            #             }
            #         else:
            #             return {
            #                 'page': 'FILES',
            #                 'files': await app['db'].user_files(None, 'Guest')
            #             }
            #     else:
            #         return {
            #             'page': 'FILES',
            #             'files': await app['db'].user_files(None, 'Guest')
            #         }
            # else:
            #     return {
            #         'page': 'FILES',
            #         'files': await app['db'].user_files(None, 'Guest')
            #     }

    @routes.view('/download')
    class WebDownloader(web.View):
        async def get(self):
                
            check = await check_timeouts(app, self.request.headers['X-Real-IP'], ['download'])
            if check:
                return aiohttp_jinja2.render_template('message.html', request = self.request, context = check)
            await app['db'].log_request(self.request.headers['X-Real-IP'], {'time': time(), 'action': 'download'})
            try:
                data = dict(urllib.parse.parse_qs(str(self.request.url)), max_num_fields = 2, strict_parsing = True)
            except ValueError: 
                try:
                    data = dict(urllib.parse.parse_qsl(await self.request.text(), max_num_fields = 2, strict_parsing = True))
                except ValueError:
                    logging.log(level = 9001, msg = "Bad file download attempt by ip: " + self.request.headers['X-Real-IP'] + " request: " + await self.request.text() + "headers: " + "")
                    return web.Response(text = "Nope", status = 500)
            print(data, flush = True)
            data['filename'] = data[str(self.request.url).split('=')[0]][0]
            if not set(data['filename']).difference(ascii_letters + digits + '.') and data['filename'] and (len(data['filename']) < 256):
                if ('AUTH' in self.request.cookies) and ('USER' in self.request.cookies):
                    cookies = dict(self.request.cookies)
                    cookies['USER'] = cookies['USER'].lower()
                    schema = {
                        'USER': {'type': 'string','maxlength': 16, 'minlength': 4, 'forbidden': ['root', 'admin', 'test', 'administrator', 'guest']}, 
                        'AUTH': {'type': 'string', 'maxlength': 64, 'minlength': 64}
                    }
                    v = cerberus.Validator(schema)
                    if v.validate(cookies) and \
                        not set(cookies['AUTH']).difference(ascii_letters + digits) and \
                        not set(cookies['USER']).difference(ascii_letters + digits):
                        if await app['db'].verify_cookie(cookies['AUTH'], cookies['USER']):
                            fileinfo = await app['db'].get_file_info(cookies['AUTH'], cookies['USER'], data['uid'][0])  
                            # print(data, flush = True)
                            # print(fileinfo, flush =  True)
                            return web.FileResponse(path = fileinfo['location'], chunk_size = 8192, headers = {'Content-Disposition': "attachment; filename=" + fileinfo['filename']})
                            #response = web.StreamResponse(content_type = 'attachment', headers = 'filename=' + fileinfo['filename'])
                            #await response.prepare()
                            #file = open(fileinfo['location'], 'rb', buffering = 8192)
                            #for chunk in file:
                            #    if chunk:
                            #        await response.write(chunk)
                            #return response.write_eof()
                            
                    else:
                        return web.Response(text = "Failed")
                else:
                    return web.Response(text = "Failed")
            else:
                return web.Response(text = "Failed")


 
                                
               

    setup_static_routes(app)
    return app.add_routes(routes)

def setup_static_routes(app):
    app.router.add_static('/static/', path = 'web_resources/jinja/static', name = 'static')

async def check_timeouts(app, ip, methods):
    for check in methods:
        match(check):
            case 'upload':
                arr = np.array([i['time'] for i in await app['db'].get_times(ip, {'action': 'upload'})])
                if list(np.logical_and(arr > (time() - 600), arr < time())).count(True) > 10:
                    context = {
                        'msg': 'Only 10 upload attempts allowed per 10 minutes',
                        'page': 'TIMEOUT'
                    }
                    logging.log(level = 9001, msg = 'File upload attempt failed by ip address: ' + ip + " due to excessive requests")
                    return context
            case 'register':
                arr = np.array([i['time'] for i in await app['db'].get_times(ip, {'action': 'register'})])
                if list(np.logical_and(arr > (time() - 1800), arr < time())).count(True) > 1:
                    context = {
                        'msg': 'Only 10 account creation attempts allowed per 30 minutes',
                        'page': 'TIMEOUT'
                    }
                    logging.log(level = 9001, msg = 'Registration attempt failed by ip address: ' + ip + " due to excessive requests")
                    return context
            case 'login':
                arr = np.array([i['time'] for i in await app['db'].get_times(ip, {'action': 'login'})])
                if list(np.logical_and(arr > (time() - 60), arr < time())).count(True) > 10:
                    context = {
                        'msg': 'Only 10 login attempts allowed per minute',
                        'page': 'TIMEOUT'
                    }
                    logging.log(level = 9001, msg = 'Login attempt failed by ip address: ' + ip + " due to excessive requests")
                    return context
            case 'download':
                arr = np.array([i['time'] for i in await app['db'].get_times(ip, {'action': 'download'})])
                if list(np.logical_and(arr > (time() - 60), arr < time())).count(True) > 10:
                    context = {
                        'msg': 'Only 10 download attempts allowed per minute',
                        'page': 'TIMEOUT'
                    }
                    logging.log(level = 9001, msg = 'Download attempt failed by ip address: ' + ip + " due to excessive requests")
                    return context
    return None


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
            'regex': '^[A-Za-z0-9]*$',
            'forbidden': ['root', 'admin', 'test', 'administrator', 'guest', 'public', 'user']
        }, 
        'AUTH': {
            'type': 'string',
            'required': True,
            'regex': '^[A-Fa-f0-9]*$',
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
async def verify_auth(app, request):
    # use parameters in body if found
    if request.has_body:
        data = await parse_request(await request.text(), 3)
        # verify parameters exist
        if not data:
            logging.log(level = 9001, msg = "Bad login attempt in body from ip address " + request.headers['X-Real-IP'] + ' Body: ' + await request.text())
            return None
    else:
        # use parameters in url
        params = str(request.url).split('?')
        # verify url split properly
        match len(params):
            # if no parameters in request
            case 1:
                logging.log(level = 9001, msg = "Login attempt by " + request.headers['X-Real-IP'] + " missing parameters Submitted URL: " +  str(request.url))
                return None
            # if 1 set of parameters found
            case 2:
                data = await parse_request(params[1], 3)
                # verify parameters exist
                if not data:
                    logging.log(level = 9001, msg = "Bad login attempt in body from ip address " + request.headers['X-Real-IP'] + ' URL: ' + str(request.url))
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
            'regex': '^[A-Za-z0-9]*$',
            'forbidden': ['root', 'admin', 'test', 'administrator', 'guest', 'public', 'user']
        }, 
        'pass': {
            'type': 'string',
            'required': True,
            'regex': '^[A-Za-z0-9]*$',
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
        # if valid verify user password matches password in database
        user = await app['db'].validate_pass(data['user'], sha256((data['pass'] + 'UWUSALT').encode()).hexdigest())
        # if valid user attempt to return to previous page
        if user:
            return [user, data['from'] if data['from'] else '/']
        # log bad credentials
        else:
            logging.log(level = 9001, msg = "Failed login attempt (bad credentials) by ip address " + request.headers['X-Real-IP'] + " for user " + data['user'])
            return None
    # if validation failed
    else:
        logging.log(level = 9001, msg = "Login failed validation requirements from ip address " + request.headers['X-Real-IP'] + " Errors: " + json.dumps(v.errors)  + " Data: " + json.dumps(data))
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
            resp.del_cookie('AUTH', domain = re.match('.*\/(.*)\/', str(request.url)).group(0)[7:-1])
            resp.del_cookie('USER', domain = re.match('.*\/(.*)\/', str(request.url)).group(0)[7:-1])
            return resp
        case 'guest':
            return aiohttp_jinja2.render_template('message.html', request = request, context = context)
        case _:
            context['user'] = r['user']
            return aiohttp_jinja2.render_template('message.html', request = request, context = context)
