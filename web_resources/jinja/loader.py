from aiohttp import request, web, MultipartReader
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
        @aiohttp_jinja2.template('index.html')
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
                            'page': 'INDEX'
                        }


    # login api
    @routes.view('/login')
    class WebLogin(web.View):
        async def get(self):
            return web.HTTPFound('/')
        async def post(self):
            # if self.request.has_body and ('AUTH' not in self.request.cookies) and ('USER' not in self.request.cookies):
            if self.request.has_body:
                check = await check_timeouts(app, self.request.headers['X-Real-IP'], ['login'])
                if check:
                    return aiohttp_jinja2.render_template('message.html', request = self.request, context = check)
                await app['db'].log_request(self.request.headers['X-Real-IP'], {'time': time(), 'action': 'login'})

                try:
                    data = dict(urllib.parse.parse_qsl(await self.request.text(), max_num_fields = 2, strict_parsing = True))
                except ValueError:
                    logging.log('Failed login attempt by ip address: ' + self.request.headers['X-Real-IP'])
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
                    userInfo = await app['db'].validate_pass(data['user'], sha256((data['pass'] + 'UWUSALT').encode()).hexdigest())
                    if userInfo: 
                        response = web.HTTPFound('/')
                        response.set_cookie('AUTH', userInfo['cookie'], domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1], samesite = "Strict")
                        response.set_cookie('USER', userInfo['user'], domain = re.match('.*\/(.*)\/', str(self.request.url)).group(0)[7:-1], samesite = "Strict")
                        return response
                else:
                    logging.log('Failed login attempt by ip address: ' + self.request.headers['X-Real-IP'])
                    return web.Response(text = "Nope", status = 500)


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
                        data['files'] = []
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
            if not((fileinfo['type'] == 'application/pdf') or (fileinfo['type'].startswith('text'))):
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
        @aiohttp_jinja2.template('viewer.html')
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
                            'page': 'FILES',
                            'files': await app['db'].user_files(cookies['AUTH'], cookies['USER'])
                        }
                    else:
                        return {
                            'page': 'FILES',
                            'files': await app['db'].user_files(None, 'Guest')
                        }
                else:
                    return {
                        'page': 'FILES',
                        'files': await app['db'].user_files(None, 'Guest')
                    }
            else:
                return {
                    'page': 'FILES',
                    'files': await app['db'].user_files(None, 'Guest')
                }
    # @routes.view('/download')
    # class WebViewer(web.View)
    #     async def get(self):
    #        if self.request.has_body:
    #             check = await check_timeouts(app, self.request.headers['X-Real-IP'], ['download'])
    #             if check:
    #                 return aiohttp_jinja2.render_template('message.html', request = self.request, context = check)
    #             await app['db'].log_request(self.request.headers['X-Real-IP'], {'time': time(), 'action': 'download'})
                
    #             try:
    #                 data = dict(urllib.parse.parse_qsl(await self.request.text(), max_num_fields = 2, strict_parsing = True))
    #             except ValueError:
    #                 logging.log(level = 9001, msg = "Attack Detected at /register: " + await self.request.text())
    #                 return web.Response(text = "Nope", status = 500)



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
