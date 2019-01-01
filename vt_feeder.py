import telegram
from telegram.ext import Updater,CommandHandler,MessageHandler,Filters
import requests
import json
import config
from time import gmtime, strftime
from datetime import datetime, timedelta
import tarfile
import os
import threading
import time

TOKEN = config.BOT_KEY
VT_KEY = config.VT_KEY
VT_directory = config.VT_DIR
whitelist = config.whitelist

updater = Updater(token=TOKEN)
bot = telegram.Bot(token=TOKEN)
dispatcher = updater.dispatcher
global rt

class repeatafterme(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.next_call = time.time()
        self.first_run()

    def first_run(self):
        fr = threading.Thread(target=self.function,args=self.args)
        fr.start()


    def _run(self):
        self.is_running = False
        self.function(*self.args, **self.kwargs)
        self.start()


    def start(self):
        if not self.is_running:
            self.next_call += self.interval
            self._timer = threading.Timer(self.next_call - time.time(), self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


def download_package(package_name):
    print("Downloading {} package".format(package_name))
    params = {'apikey': VT_KEY, 'package': package_name}
    resp = requests.get('https://www.virustotal.com/vtapi/v2/file/feed' , params=params)
    if resp.ok:
        package_name += '.tar.bz2'
        package_file = open(VT_directory+'package/'+package_name,'wb')
        package_file.write(resp.content)
        package_file.close()
        return package_name
    else:
        return 'bad'

def parse_package(package_name):
    hash_list =[]

    with tarfile.open(VT_directory+'package/'+package_name, mode='r:bz2') as compressed:
        print('alo')
        for member in compressed.getmembers():
            member_file = compressed.extractfile(member)
            for line in member_file:
                item_json = line.decode("utf-8").strip('\n')
                if not item_json:
                    print('bad')
                    continue
                item_report = json.loads(item_json)
                print(item_report.get('sha256'))
                hash_list.append(item_report.get('sha256'))

    return hash_list

def download_files(hash_list):
    good = 0
    for link in hash_list:
        url = 'https://www.virustotal.com/intelligence/download/?hash={}&apikey={}'.format(link,VT_KEY)
        resp = requests.get(url)
        if resp.ok:
            f = open(VT_directory+link,'wb')
            f.write(resp.content)
            f.close()
            good += 1

    return good


def downloader(chat_id):
    bot.send_message(chat_id,'Downloading started..')
    time_string =strftime("%Y%m%dT%H00", gmtime())
    pack = download_package(time_string)
    if pack == 'bad':
        bot.send_message(chat_id,'Couldn\'t download package {}'.format(time_string))

    hash_list = parse_package(pack)
    bot.send_message(chat_id,'Hash list : {} . This could take a while'.format(len(hash_list)))
    download_count = download_files(hash_list)
    bot.send_message(chat_id,'{}/{} downloaded, {}'.format(download_count,len(hash_list),time_string))

def list_packages(bot,update):
    files = [f for f in os.listdir(VT_directory+'package/')]
    m = ' Count {}\n'.format(len(files))
    m += '\n'.join(files)
    bot.send_message(update.message.chat_id,m)

def start_d(bot,update):
    global rt
    rt = repeatafterme(60*60,downloader,whitelist[0])
    rt.start()
    bot.send_message(update.message.chat_id,'VT Feeder started.')

def stop_d(bot,update):
    global rt
    rt.stop()
    bot.send_message(update.message.chat_id,'VT Feeder stopped')

def is_running(bot,update):
    global rt
    bot.send_message(update.message.chat_id,'? VT Feeder is running : {}'.format(rt.is_running))
    if rt.is_running:
        time_c = rt.next_call - time.time()
        bot.send_message(update.message.chat_id,'next call in {} second'.format(int(time_c)))

def chat_id(bot,update):
    bot.send_message(update.message.chat_id,update.message.chat_id)

def _help(bot,update):
    m = 'start_d\nstop_d\nis_running\nlist_packages\nhelp'
    bot.send_message(update.message.chat_id,m)

def check_allowed(bot,update):
    if update.message.chat_id not in whitelist:
        bot.send_message(whitelist[0],'Watchout strangers..')

if __name__ == "__main__":
    if not os.path.isdir(VT_directory):
        print('Creating VT_dir')
        os.makedirs(VT_directory)

    if not os.path.isdir(VT_directory+'package'):
        print('Creating dir')
        os.makedirs(VT_directory+'package')

    loop_start_handler = CommandHandler('start_d',start_d)
    chat_handler = CommandHandler('chat_id',chat_id)
    loop_stop_handler = CommandHandler('stop_d',stop_d)
    is_handler = CommandHandler('is_running',is_running)
    list_handler = CommandHandler('list_packages',list_packages)
    help_handler = CommandHandler('help',_help)

    #dispatcher.add_handler(MessageHandler(Filters.all, check_allowed),-1)
    dispatcher.add_handler(list_handler)
    dispatcher.add_handler(help_handler)
    dispatcher.add_handler(chat_handler)
    dispatcher.add_handler(loop_start_handler)
    dispatcher.add_handler(loop_stop_handler)
    dispatcher.add_handler(is_handler)
    updater.start_polling()
