import json
from pushbullet import Pushbullet
from datetime import datetime
from dateutil import tz
import sys
import groupme
import os
import twitter

# Fixes the encoding of the male/female symbol
reload(sys)
sys.setdefaultencoding('utf8')

pushbullet_client = None
wanted_pokemon = None
unwanted_pokemon = None

# Initialize object
def init():
    global pushbullet_client, wanted_pokemon, unwanted_pokemon
    # load pushbullet key
    with open('config.json') as data_file:
        data = json.load(data_file)
        # get list of pokemon to send notifications for
        if "notify" in data:
            wanted_pokemon = _str( data["notify"] ) . split(",")

            # transform to lowercase
            wanted_pokemon = [a.lower() for a in wanted_pokemon]
        #get list of pokemon to NOT send notifications for
        if "do_not_notify" in data:
            unwanted_pokemon = _str( data["do_not_notify"] ) . split(",")

            # transform to lowercase
            unwanted_pokemon = [a.lower() for a in unwanted_pokemon]
        # get api key
        api_key = _str( data["pushbullet"] )
        if api_key:
            pushbullet_client = Pushbullet(api_key)


# Safely parse incoming strings to unicode
def _str(s):
  return s.encode('utf-8').strip()


def convert_timestamp(timestamp):
    # METHOD 1: Hardcode zones:
    from_zone = tz.tzlocal()
    to_zone = tz.gettz('America/New_York')

    # utc = datetime.utcnow()
    utc = datetime.fromtimestamp(timestamp)

    # Tell the datetime object that it's in UTC time zone since 
    # datetime objects are 'naive' by default
    utc = utc.replace(tzinfo=from_zone)

    # Convert time zone
    est = utc.astimezone(to_zone)

    return est.strftime("%-I:%M:%S %p")

# Notify user for discovered Pokemon
def pokemon_found(pokemon):
    # get name
    pokename = _str(pokemon["name"]).lower()
    # check array
    if not pushbullet_client:
        return
    elif wanted_pokemon != None and not pokename in wanted_pokemon:
        return
    elif wanted_pokemon == None and unwanted_pokemon != None and pokename in unwanted_pokemon:
        return
    # notify
    print "[+] Notifier found pokemon:", pokename

    #http://maps.google.com/maps/place/<place_lat>,<place_long>/@<map_center_lat>,<map_center_long>,<zoom_level>z
    latLon = '{},{}'.format(repr(pokemon["lat"]), repr(pokemon["lng"]))
    google_maps_link = 'http://maps.google.com/maps/place/{}/@{},{}z'.format(latLon, latLon, 20)

    disappear_time = convert_timestamp(pokemon['disappear_time'])

    bot_id = os.environ['BOT_ID']
    groupme_message = 'A wild {} appeared at {} and will be available until {}.'.format(_str(pokemon['name']), google_maps_link, disappear_time)
    groupme.send_message(groupme_message, bot_id)
    twitter.tweet(groupme_message)

init()
