from aiohttp import web
import aiohttp_jinja2, jinja2
import logging

from web_resources.jinja.driver import setup_routes

logging.basicConfig(
    level = logging.WARNING,
    filename = "/logs/webapp.log",
    format = '%(asctime)s %(message)s',
    datefmt = '%m/%d/%Y %I:%M:%S %p'
)

async def run_webapp(database):
    webapp = web.Application(logger = logging.getLogger(), client_max_size = ((1024 ** 2) * 50))
    webapp['db'] = database
    aiohttp_jinja2.setup(webapp, loader = jinja2.PackageLoader('web_resources.jinja', 'templates'))
    setup_routes(webapp)
    return webapp