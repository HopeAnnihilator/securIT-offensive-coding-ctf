from pymongo import MongoClient, errors
from time import time, gmtime, strftime
import json

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
        
    async def user_files(self, user):
        return self.client['files'][user.lower()].find()
        # if await self.check_user_exists(user) and (user.lower() != 'guest'):
        #     return self.client['users'][user.lower()].find_one({'cookie': cookie})['files']
        # elif (user.lower() == 'guest'):
        #     return self.client['users'][user.lower()].find({'author': 'Guest'})
        # else:
        #     return None
    
    async def add_file_user(self, user, data):
        self.client['files'][user.lower()].insert_one(data)

            
    async def log_request(self, ipAdd, data):
        self.client['logs'][strftime('%b-%d-%Y-', gmtime()) + ipAdd].insert_one(data)

    async def get_times(self, ipAdd, filter):
        return self.client['logs'][strftime('%b-%d-%Y-', gmtime()) + ipAdd].find(filter)

    async def get_file_info(self, user, uid):
        return self.client['files'][user.lower()].find_one({'uid': uid})
    
    async def get_timeout_object(self, ipAdd, method):
        return self.client['timeouts'][ipAdd].find_one({'method': method})

    async def increment_timeout_counter(self, ipAdd, method, obj):
        obj['time'][0] += 1
        self.client['timeouts'][ipAdd].replace_one({'method': method}, obj)

    async def add_new_timeout_object(self, ipAdd, method):
        self.client['timeouts'][ipAdd].insert_one({'method': method, 'time': json.dumps([1, time()])})
    
    async def reset_timeout_object(self, ipAdd, method):
        self.client['timeouts'][ipAdd].replace_one({'method': method, 'time': json.dumps([1, time()])})