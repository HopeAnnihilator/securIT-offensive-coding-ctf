from aiohttp import web
import aiohttp_jinja2, jinja2

from web_resources.jinja.driver import setup_routes

async def run_webapp(database):
    webapp = web.Application()
    webapp['db'] = database
    aiohttp_jinja2.setup(webapp, loader = jinja2.PackageLoader('web_resources.jinja', 'templates'))
    setup_routes(webapp)
    return webapp