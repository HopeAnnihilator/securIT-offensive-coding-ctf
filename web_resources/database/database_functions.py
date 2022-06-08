from pymongo import MongoClient, errors
from time import time, gmtime, strftime

class mongodb:
    def __init__(self):
        self.client = MongoClient(
            host = 'thingy-mongo', 
            port = 27017, 
            username = 'root', 
            password = 'isItCheatingToReadThis', 
            authSource = 'admin'
        )
    
    async def insert(self, db_name, db_col, data):
        database = self.client[db_name]
        column = database[db_col]
        column.insert_one(data)

    async def database_exists(self, db_name):
        return db_name in self.client.list_database_names()

    async def fetch_all_objects(self, db_name, db_col):
        database = self.client[db_name]
        return database[db_col].find().distinct('_id')

    async def fetch_collection(self, db_name, db_col):
        database = self.client[db_name]
        return database.get_collection(db_col)
    
    async def check_user_exists(self, user):
        return user.lower() in self.client['users'].list_collection_names()
    
    async def add_user(self, user, data):
        self.client['users'][user.lower()].insert_one(document = data)
    
    async def add_timeout(self, ipAdd, endTime, reason):
        self.client['timeouts'][ipAdd].insert_one({reason: endTime})

    async def check_timeout(self, ipAdd, reason):
        for document in self.client['timeouts'][ipAdd].find():
            if reason in document.keys():
                if time() < document[reason]:
                    return True
        return False

    async def verify_cookie(self, cookie, user):
        return self.client['users'][user.lower()].find_one({'cookie': cookie})

    async def validate_pass(self, user, password):
        return self.client['users'][user.lower()].find_one({'pass': password})
        
    async def user_files(self, cookie, user):
        if await self.check_user_exists(user) and (user != 'Guest'):
            return self.client['users'][user.lower()].find_one({'cookie': cookie})['files']
        elif (user == 'Guest'):
            return self.client['users'][user.lower()].find({'author': 'Guest'})
        else:
            return None
    
    async def add_file_user(self, cookie, user, data):
        if await self.check_user_exists(user) and (user != 'Guest'):
            if await self.verify_cookie(cookie, user):
                self.client['users'][user.lower()].insert_one({data})
        elif user == 'Guest':
            self.client['users'][user.lower()].insert_one({data})
            
    async def log_request(self, ipAdd, data):
        self.client['logs'][strftime('%b-%d-%Y-', gmtime()) + ipAdd].insert_one(data)

    async def get_times(self, ipAdd, filter):
        return self.client['logs'][strftime('%b-%d-%Y-', gmtime()) + ipAdd].find(filter)

    async def get_file_info(self, cookie, user, uid):
        if await self.check_user_exists(user) and (user != 'Guest'):
            files = self.client['users'][user.lower()].find_one({'cookie': cookie})['files']
            for file in files:
                if file['uid'] == uid:
                    return file
            return None
        elif (user == 'Guest'):
            pass

    
