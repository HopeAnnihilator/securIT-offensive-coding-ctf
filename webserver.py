import logging
from web_resources.app.webapp import run_webapp
from web_resources.database.database_functions import mongodb

logging.basicConfig(
    level = logging.WARNING,
    filename = "/logs/webapp.log",
    format = '%(asctime)s %(message)s',
    datefmt = '%m/%d/%Y %I:%M:%S %p'
)

async def start():
    database = mongodb()
    return await run_webapp(database)

