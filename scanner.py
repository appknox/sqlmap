# modules from mars
import os
import json
import sqlite3
import subprocess
import configparser

# modules from sqlmap
from lib.core.convert import hexencode

IS_WIN = subprocess._mswindows


class Scanner(object):
    def __init__(self, database=None, json_file=None):
        self.database = '/tmp/sqlmapipc' + str(hexencode(os.urandom(8))) if database is None else database
        self.json_file = json_file
        self.taskid = hexencode(os.urandom(8))
        self.configFile = '/tmp/baseConfig'  # Needs imrovement

    def connect(self):
        self.connection = sqlite3.connect(
            self.database, timeout=3,
            isolation_level=None, check_same_thread=False)
        self.cursor = self.connection.cursor()
        print(('DB Connection Success ' + self.database))

    def disconnect(self):
        if self.cursor:
            self.cursor.close()

        if self.connection:
            self.connection.close()

    def execute(self, statement, arguments=None):
        while True:
            try:
                if arguments:
                    self.cursor.execute(statement, arguments)
                else:
                    self.cursor.execute(statement)
            except sqlite3.OperationalError as ex:
                print('----------------------------------------')
                print(ex)
                print('----------------------------------------')
            else:
                break

        if statement.lstrip().upper().startswith("SELECT"):
            return self.cursor.fetchall()

    def jsonize(self, data):
        """
        Returns JSON serialized data

        >>> jsonize({'foo':'bar'})
        '{\\n    "foo": "bar"\\n}'
        """

        return json.dumps(data, sort_keys=False, indent=4)

    def dejsonize(self, data):
        """
        Returns JSON deserialized data

        >>> dejsonize('{\\n    "foo": "bar"\\n}')
        {u'foo': u'bar'}
        """

        return json.loads(data)

    def initdb(self):
        print('DB Initialized!')
        self.execute("CREATE TABLE logs(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, time TEXT, level TEXT, message TEXT)")
        self.execute("CREATE TABLE data(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, status INTEGER, content_type INTEGER, value TEXT)")
        self.execute("CREATE TABLE errors(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, error TEXT)")

    def get_data(self, taskid):
        print(('Feching Data for taskid:' + taskid))
        json_data_message = list()
        for status, content_type, value in self.cursor.execute("SELECT status, content_type, value FROM data WHERE taskid = ? ORDER BY id ASC", (taskid,)):
                json_data_message.append({"status": status, "type": content_type, "value": self.dejsonize(value)})

        print('----------------------------------------')
        print(json_data_message)
        print('----------------------------------------')
        return self.jsonize(json_data_message)

    def engine_process(self):
        print('Engine Started!')
        json_data = json.load(open(self.json_file))
        print((json_data[0]['host']+json_data[0]['path']))
        for url in json_data:
            config = configparser.ConfigParser()
            config.read(self.configFile)
            config.set('API', 'database', self.database)
            config.set('API', 'taskid', self.taskid)
            config.set('Target', 'url', url['host'] + url['path'])
            config.set('Request', 'host', url['headers']['Host'])
            config.set('Request', 'agent', url['headers']['User-Agent'])
            config.set('Request', 'referer', url['headers']['Referer'])
            config.set('Request', 'cookie', url['headers']['Cookie'])
            config.set('Request', 'method', url['method'])
            for_header = 'Accept:' + url['headers']['Accept'] + '\n Accept-Encoding:' + url['headers']['Accept-Encoding'] + '\n Accept-Language:' + url['headers']['Accept-Language'] \
            + '\n Cache-Control:' + url['headers']['Cache-Control'] + '\n Connection:' + url['headers']['Connection'] + '\n Content-Length:' + url['headers']['Content-Length'] \
            + '\n Content-Type:' + url['headers']['Content-Type']
            config.set('Request', 'headers', for_header)

            formData = "uname=subham&pass=password"
            config.set('Request', 'data', formData)

            with open(self.configFile, 'wb') as fp:
                config.write(fp)

            self.process = subprocess.Popen(
                ["python", "sqlmap.py", "--api", "-c", self.configFile],
                shell=False, close_fds=not IS_WIN)

            self.process.wait()
        print('Engine Processed!')
        return self.get_data(self.taskid)
