import re
import requests
from katti.DataBaseStuff.Helpers import execute_bulk_ops
from pymongo import UpdateOne
from katti.DataBaseStuff.ConnectDisconnect import connect_to_database
from katti.DataBaseStuff.MongoengineDocuments.Crawling.HTTPRequestHeader import UserAgentString

Browser_list = ['Chrome', 'Firefox', 'Edge', 'Safari']

def update_strings():
    connect_to_database()
    bulk_ops = []
    collection = UserAgentString()._get_collection()
    for browser in Browser_list:
        try:
            print(f'Next browser {browser}')
            respone = requests.get(f'https://useragentstring.com/pages/{browser}/')

            if not respone.status_code == 200:
                print(f'Bad stuff: {respone.status_code}, browser {browser}')
            else:
                html = respone.content.decode('utf-8')
                html = html.split("<div id='liste'>")[1]
                html = html.split("</div>")[0]

                pattern = r"<a href=\'/.*?>(.+?)</a>"
                browsers_iter = re.finditer(pattern, html, re.UNICODE)

                for browser_resp in browsers_iter:
                    if "more" in browser_resp.group(1).lower():
                        continue
                    browser_type = browser_resp.group(0).split("<a href='/")[-1].split(".php")[0]
                    bulk_ops.append(UpdateOne({'browser': browser, 'browser_version': str(browser_type)}, {'$setOnInsert': {'ua_string': str(browser_resp.group(1))}}, upsert=True))
                    bulk_ops = execute_bulk_ops(collection=collection, bulk_ops=bulk_ops, min_ops=100)
        except Exception as e:
            print(e)
        execute_bulk_ops(collection=collection, bulk_ops=bulk_ops, force=True)


if __name__ == '__main__':
    update_strings()