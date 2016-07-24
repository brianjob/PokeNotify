#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import sys
import struct
import json
import requests
import argparse
import getpass
import pokemon_pb2
import time
import warnings
import notifier
from google.protobuf.internal import encoder
from google.protobuf.message import DecodeError
from s2sphere import *
from datetime import datetime, timedelta
from geopy.geocoders import GoogleV3
from gpsoauth import perform_master_login, perform_oauth
from geopy.exc import GeocoderTimedOut, GeocoderServiceError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.adapters import ConnectionError
from requests.models import InvalidURL
from requests.exceptions import ReadTimeout
from transform import *

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

API_URL = 'https://pgorelease.nianticlabs.com/plfe/rpc'
LOGIN_URL = \
    'https://sso.pokemon.com/sso/login?service=https://sso.pokemon.com/sso/oauth2.0/callbackAuthorize'
LOGIN_OAUTH = 'https://sso.pokemon.com/sso/oauth2.0/accessToken'
APP = 'com.nianticlabs.pokemongo'

with open('credentials.json') as file:
	credentials = json.load(file)

PTC_CLIENT_SECRET = credentials.get('ptc_client_secret', None)
ANDROID_ID = credentials.get('android_id', None)
SERVICE = credentials.get('service', None)
CLIENT_SIG = credentials.get('client_sig', None)
GOOGLEMAPS_KEY = credentials.get('gmaps_key', None)

SESSION = requests.session()
SESSION.headers.update({'User-Agent': 'Niantic App'})
SESSION.verify = False

global_password = None
global_token = None
access_token = None
DEBUG = True
VERBOSE_DEBUG = False  # if you want to write raw request/response to the console
COORDS_LATITUDE = 0
COORDS_LONGITUDE = 0
COORDS_ALTITUDE = 0
FLOAT_LAT = 0
FLOAT_LONG = 0
NEXT_LAT = 0
NEXT_LONG = 0
auto_refresh = 0
default_step = 0.001
api_endpoint = None
pokemons = {}

origin_lat, origin_lon = None, None
is_ampm_clock = False


def parse_unicode(bytestring):
    decoded_string = bytestring.decode(sys.getfilesystemencoding())
    return decoded_string


def debug(message):
    if DEBUG:
        print '[-] {}'.format(message)


def time_left(ms):
    s = ms / 1000
    (m, s) = divmod(s, 60)
    (h, m) = divmod(m, 60)
    return (h, m, s)


def encode(cellid):
    output = []
    encoder._VarintEncoder()(output.append, cellid)
    return ''.join(output)


def getNeighbors():
    origin = CellId.from_lat_lng(LatLng.from_degrees(FLOAT_LAT,
                                                     FLOAT_LONG)).parent(15)
    walk = [origin.id()]

    # 10 before and 10 after

    next = origin.next()
    prev = origin.prev()
    for i in range(10):
        walk.append(prev.id())
        walk.append(next.id())
        next = next.next()
        prev = prev.prev()
    return walk


def f2i(float):
    return struct.unpack('<Q', struct.pack('<d', float))[0]


def f2h(float):
    return hex(struct.unpack('<Q', struct.pack('<d', float))[0])


def h2f(hex):
    return struct.unpack('<d', struct.pack('<Q', int(hex, 16)))[0]


def retrying_set_location(location_name):
    """
    Continue trying to get co-ords from Google Location until we have them
    :param location_name: string to pass to Location API
    :return: None
    """

    while True:
        try:
            set_location(location_name)
            return
        except (GeocoderTimedOut, GeocoderServiceError), e:
            debug(
                'retrying_set_location: geocoder exception ({}), retrying'.format(
                    str(e)))
        time.sleep(1.25)


def set_location(location_name):
    geolocator = GoogleV3()
    prog = re.compile('^(\-?\d+(\.\d+)?),\s*(\-?\d+(\.\d+)?)$')
    global origin_lat
    global origin_lon
    if prog.match(location_name):
        local_lat, local_lng = [float(x) for x in location_name.split(",")]
        alt = 0
        origin_lat, origin_lon = local_lat, local_lng
    else:
        loc = geolocator.geocode(location_name)
        origin_lat, origin_lon = local_lat, local_lng = loc.latitude, loc.longitude
        alt = loc.altitude
        print '[!] Your given location: {}'.format(loc.address.encode('utf-8'))

    print('[!] lat/long/alt: {} {} {}'.format(local_lat, local_lng, alt))
    set_location_coords(local_lat, local_lng, alt)


def set_location_coords(lat, long, alt):
    global COORDS_LATITUDE, COORDS_LONGITUDE, COORDS_ALTITUDE
    global FLOAT_LAT, FLOAT_LONG
    FLOAT_LAT = lat
    FLOAT_LONG = long
    COORDS_LATITUDE = f2i(lat)  # 0x4042bd7c00000000 # f2i(lat)
    COORDS_LONGITUDE = f2i(long)  # 0xc05e8aae40000000 #f2i(long)
    COORDS_ALTITUDE = f2i(alt)


def get_location_coords():
    return (COORDS_LATITUDE, COORDS_LONGITUDE, COORDS_ALTITUDE)


def retrying_api_req(service, api_endpoint, access_token, *args, **kwargs):
    while True:
        try:
            response = api_req(service, api_endpoint, access_token, *args,
                               **kwargs)
            if response:
                return response
            debug('retrying_api_req: api_req returned None, retrying')
        except (InvalidURL, ConnectionError, DecodeError, ReadTimeout), e:
            debug('retrying_api_req: request error ({}), retrying'.format(
                str(e)))
        time.sleep(1)


def api_req(service, api_endpoint, access_token, *args, **kwargs):
    p_req = pokemon_pb2.RequestEnvelop()
    p_req.rpc_id = 1469378659230941192

    p_req.unknown1 = 2

    (p_req.latitude, p_req.longitude, p_req.altitude) = \
        get_location_coords()

    p_req.unknown12 = 989

    if 'useauth' not in kwargs or not kwargs['useauth']:
        p_req.auth.provider = service
        p_req.auth.token.contents = access_token
        p_req.auth.token.unknown13 = 14
    else:
        p_req.unknown11.unknown71 = kwargs['useauth'].unknown71
        p_req.unknown11.unknown72 = kwargs['useauth'].unknown72
        p_req.unknown11.unknown73 = kwargs['useauth'].unknown73

    for arg in args:
        p_req.MergeFrom(arg)

    protobuf = p_req.SerializeToString()

    r = SESSION.post(api_endpoint, data=protobuf, verify=False)

    p_ret = pokemon_pb2.ResponseEnvelop()
    p_ret.ParseFromString(r.content)

    if VERBOSE_DEBUG:
        print 'REQUEST:'
        print p_req
        print 'Response:'
        print p_ret
        print '''
'''
    time.sleep(0.51)
    return p_ret


def get_api_endpoint(service, access_token, api=API_URL):
    profile_response = None
    while not profile_response:
        profile_response = retrying_get_profile(service, access_token, api,
                                                None)
        if not hasattr(profile_response, 'api_url'):
            debug(
                'retrying_get_profile: get_profile returned no api_url, retrying')
            profile_response = None
            continue
        if not len(profile_response.api_url):
            debug(
                'get_api_endpoint: retrying_get_profile returned no-len api_url, retrying')
            profile_response = None

    return 'https://%s/rpc' % profile_response.api_url

def retrying_get_profile(service, access_token, api, useauth, *reqq):
    profile_response = None
    while not profile_response:
        profile_response = get_profile(service, access_token, api, useauth,
                                       *reqq)
        if not hasattr(profile_response, 'payload'):
            debug(
                'retrying_get_profile: get_profile returned no payload, retrying')
            profile_response = None
            continue
        if not profile_response.payload:
            debug(
                'retrying_get_profile: get_profile returned no-len payload, retrying')
            profile_response = None

    return profile_response

def get_profile(service, access_token, api, useauth, *reqq):
    req = pokemon_pb2.RequestEnvelop()
    req1 = req.requests.add()
    req1.type = 2
    if len(reqq) >= 1:
        req1.MergeFrom(reqq[0])

    req2 = req.requests.add()
    req2.type = 126
    if len(reqq) >= 2:
        req2.MergeFrom(reqq[1])

    req3 = req.requests.add()
    req3.type = 4
    if len(reqq) >= 3:
        req3.MergeFrom(reqq[2])

    req4 = req.requests.add()
    req4.type = 129
    if len(reqq) >= 4:
        req4.MergeFrom(reqq[3])

    req5 = req.requests.add()
    req5.type = 5
    if len(reqq) >= 5:
        req5.MergeFrom(reqq[4])
    return retrying_api_req(service, api, access_token, req, useauth=useauth)

def login_google(username, password):
    print '[!] Google login for: {}'.format(username)
    r1 = perform_master_login(username, password, ANDROID_ID)
    r2 = perform_oauth(username,
                       r1.get('Token', ''),
                       ANDROID_ID,
                       SERVICE,
                       APP,
                       CLIENT_SIG, )
    return r2.get('Auth')

def login_ptc(username, password):
    print '[!] PTC login for: {}'.format(username)
    head = {'User-Agent': 'Niantic App'}
    r = SESSION.get(LOGIN_URL, headers=head)
    if r is None:
        return render_template('nope.html', fullmap=fullmap)

    try:
        jdata = json.loads(r.content)
    except ValueError, e:
        debug('login_ptc: could not decode JSON from {}'.format(r.content))
        return None

    # Maximum password length is 15 (sign in page enforces this limit, API does not)

    if len(password) > 15:
        print '[!] Trimming password to 15 characters'
        password = password[:15]

    data = {
        'lt': jdata['lt'],
        'execution': jdata['execution'],
        '_eventId': 'submit',
        'username': username,
        'password': password,
    }
    r1 = SESSION.post(LOGIN_URL, data=data, headers=head)

    ticket = None
    try:
        ticket = re.sub('.*ticket=', '', r1.history[0].headers['Location'])
    except Exception, e:
        if DEBUG:
            print r1.json()['errors'][0]
        return None

    data1 = {
        'client_id': 'mobile-app_pokemon-go',
        'redirect_uri': 'https://www.nianticlabs.com/pokemongo/error',
        'client_secret': PTC_CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'code': ticket,
    }
    r2 = SESSION.post(LOGIN_OAUTH, data=data1)
    access_token = re.sub('&expires.*', '', r2.content)
    access_token = re.sub('.*access_token=', '', access_token)

    return access_token


def get_heartbeat(service,
                  api_endpoint,
                  access_token,
                  response, ):
    m4 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleInt()
    m.f1 = int(time.time() * 1000)
    m4.message = m.SerializeToString()
    m5 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleString()
    m.bytes = '05daf51635c82611d1aac95c0b051d3ec088a930'
    m5.message = m.SerializeToString()
    walk = sorted(getNeighbors())
    m1 = pokemon_pb2.RequestEnvelop.Requests()
    m1.type = 106
    m = pokemon_pb2.RequestEnvelop.MessageQuad()
    m.f1 = ''.join(map(encode, walk))
    m.f2 = \
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
    m.lat = COORDS_LATITUDE
    m.long = COORDS_LONGITUDE
    m1.message = m.SerializeToString()
    response = get_profile(service,
                           access_token,
                           api_endpoint,
                           response.unknown7,
                           m1,
                           pokemon_pb2.RequestEnvelop.Requests(),
                           m4,
                           pokemon_pb2.RequestEnvelop.Requests(),
                           m5, )

    try:
        payload = response.payload[0]
    except (AttributeError, IndexError):
        return

    heartbeat = pokemon_pb2.ResponseEnvelop.HeartbeatPayload()
    heartbeat.ParseFromString(payload)
    return heartbeat

def get_token(service, username, password):
    """
    Get token if it's not None
    :return:
    :rtype:
    """

    global global_token
    if global_token is None:
        if service == 'ptc':
            global_token = login_ptc(username, password)
        else:
            global_token = login_google(username, password)
        return global_token
    else:
        return global_token



def get_args():
    # load default args
    default_args = {
        "DEBUG": True,
        "ampm_clock": False,
        "auth_service": "ptc",
        "auto_refresh": None,
        "china": False,
        "debug": False,
        "display_gym": False,
        "display_pokestop": False,
        "do_not_notify": None,
        "host": "127.0.0.1",
        "ignore": None,
        "locale": "en",
        "location": None,
        "notify": None,
        "only": None,
        "onlylure": False,
        "password": None,
        "port": 3030,
        "pushbullet": None,
        "step_limit": 4,
        "username": None
    }

    INTEGER_STR = "int"
    BOOLEAN_STR = "bool"
    STRING_STR = "str"
    default_args_type = {
        "DEBUG": BOOLEAN_STR,
        "ampm_clock": BOOLEAN_STR,
        "auth_service": STRING_STR,
        "auto_refresh": INTEGER_STR,
        "china": BOOLEAN_STR,
        "debug": BOOLEAN_STR,
        "display_gym": BOOLEAN_STR,
        "display_pokestop": BOOLEAN_STR,
        "do_not_notify": STRING_STR,
        "host": STRING_STR,
        "ignore": STRING_STR,
        "locale": STRING_STR,
        "location": STRING_STR,
        "notify": STRING_STR,
        "only": STRING_STR,
        "onlylure": BOOLEAN_STR,
        "password": STRING_STR,
        "port": INTEGER_STR,
        "pushbullet": STRING_STR,
        "step_limit": INTEGER_STR,
        "username": STRING_STR
    }
    # load config file
    with open('config.json') as data_file:
        data = json.load(data_file)
        for key in data:
            if key not in default_args_type:
                warnings.warn( 'Config Item ' + key + 'Does Not Have a Default Type' )

            if default_args_type[key] == INTEGER_STR:
                default_args[key] = int(data[key])

            elif default_args_type[key] == BOOLEAN_STR:
                default_args[key] = data[key]

            else:
                if default_args_type[key] != STRING_STR:
                    warnings.warn( 'Unsupported Default Args Type' )

                default_args[key] = str(data[key])
        # create namespace obj
        namespace = argparse.Namespace()
        for key in default_args:
            vars(namespace)[key] = default_args[key]
        return namespace

def login(args):
    global global_password
    if not global_password:
      if args.password:
        global_password = args.password
      else:
        global_password = getpass.getpass()

    access_token = get_token(args.auth_service, args.username, global_password)
    if access_token is None:
        raise Exception('[-] Wrong username/password')

    print '[+] RPC Session Token: {} ...'.format(access_token[:25])

    api_endpoint = get_api_endpoint(args.auth_service, access_token)
    if api_endpoint is None:
        raise Exception('[-] RPC server offline')

    print '[+] Received API endpoint: {}'.format(api_endpoint)

    profile_response = retrying_get_profile(args.auth_service, access_token,
                                            api_endpoint, None)
    if profile_response is None or not profile_response.payload:
        raise Exception('Could not get profile')

    print '[+] Login successful'

    payload = profile_response.payload[0]
    profile = pokemon_pb2.ResponseEnvelop.ProfilePayload()
    profile.ParseFromString(payload)
    print '[+] Username: {}'.format(profile.profile.username)

    creation_time = \
        datetime.fromtimestamp(int(profile.profile.creation_time)
                               / 1000)
    print '[+] You started playing Pokemon Go on: {}'.format(
        creation_time.strftime('%Y-%m-%d %H:%M:%S'))

    for curr in profile.profile.currency:
        print '[+] {}: {}'.format(curr.type, curr.amount)

    return api_endpoint, access_token, profile_response


def main():
    start = datetime.now()

    full_path = os.path.realpath(__file__)
    (path, filename) = os.path.split(full_path)

    args = get_args()

    if args.auth_service not in ['ptc', 'google']:
        print '[!] Invalid Auth service specified'
        return

    print('[+] Locale is ' + args.locale)
    pokemonsJSON = json.load(
        open(path + '/locales/pokemon.' + args.locale + '.json'))

    if args.debug:
        global DEBUG
        DEBUG = True
        print '[!] DEBUG mode on'

    # only get location for first run
    if not (FLOAT_LAT and FLOAT_LONG):
      print('[+] Getting initial location')
      retrying_set_location(args.location)

    if args.auto_refresh:
        global auto_refresh
        auto_refresh = int(args.auto_refresh) * 1000

    if args.ampm_clock:
    	global is_ampm_clock
    	is_ampm_clock = True

    while datetime.now() - start < timedelta(minutes=6):
        scan(args, pokemonsJSON)

    print 'Program completed in {}'.format(str(datetime.now() - start))


# run a scan of area
def scan(args, pokemonsJSON):
    api_endpoint, access_token, profile_response = login(args)

    clear_stale_pokemons()

    steplimit = int(args.step_limit)

    ignore = []
    only = []
    if args.ignore:
        ignore = [i.lower().strip() for i in args.ignore.split(',')]
    elif args.only:
        only = [i.lower().strip() for i in args.only.split(',')]

    pos = 1
    x = 0
    y = 0
    dx = 0
    dy = -1
    steplimit2 = steplimit**2
    for step in range(steplimit2):
        debug('looping: step {} of {}'.format((step+1), steplimit**2))
        if -steplimit2 / 2 < x <= steplimit2 / 2 and -steplimit2 / 2 < y <= steplimit2 / 2:
            set_location_coords(x * 0.0025 + origin_lat, y * 0.0025 + origin_lon, 0)
        if x == y or x < 0 and x == -y or x > 0 and x == 1 - y:
            (dx, dy) = (-dy, dx)

        (x, y) = (x + dx, y + dy)

        process_step(args, api_endpoint, access_token, profile_response,
                     pokemonsJSON, ignore, only)

        print('Completed: ' + str(
            ((step+1) + pos * .25 - .25) / (steplimit2) * 100) + '%')

    global NEXT_LAT, NEXT_LONG
    if (NEXT_LAT and NEXT_LONG and
            (NEXT_LAT != FLOAT_LAT or NEXT_LONG != FLOAT_LONG)):
        print('Update to next location %f, %f' % (NEXT_LAT, NEXT_LONG))
        set_location_coords(NEXT_LAT, NEXT_LONG, 0)
        NEXT_LAT = 0
        NEXT_LONG = 0
    else:
        set_location_coords(origin_lat, origin_lon, 0)


def process_step(args, api_endpoint, access_token, profile_response,
                 pokemonsJSON, ignore, only):
    print('[+] Searching for Pokemon at location {} {}'.format(FLOAT_LAT, FLOAT_LONG))
    origin = LatLng.from_degrees(FLOAT_LAT, FLOAT_LONG)
    step_lat = FLOAT_LAT
    step_long = FLOAT_LONG
    parent = CellId.from_lat_lng(LatLng.from_degrees(FLOAT_LAT,
                                                     FLOAT_LONG)).parent(15)
    h = get_heartbeat(args.auth_service, api_endpoint, access_token,
                      profile_response)
    hs = [h]
    seen = {}

    for child in parent.children():
        latlng = LatLng.from_point(Cell(child).get_center())
        set_location_coords(latlng.lat().degrees, latlng.lng().degrees, 0)
        hs.append(
            get_heartbeat(args.auth_service, api_endpoint, access_token,
                          profile_response))
    set_location_coords(step_lat, step_long, 0)
    visible = []

    for hh in hs:
        try:
            for cell in hh.cells:
                for wild in cell.WildPokemon:
                    hash = wild.SpawnPointId;
                    if hash not in seen.keys() or (seen[hash].TimeTillHiddenMs <= wild.TimeTillHiddenMs):
                        visible.append(wild)
                    seen[hash] = wild.TimeTillHiddenMs
        except AttributeError:
            break

    for poke in visible:
        pokeid = str(poke.pokemon.PokemonId)
        pokename = pokemonsJSON[pokeid]
        if args.ignore:
            if pokename.lower() in ignore or pokeid in ignore:
                continue
        elif args.only:
            if pokename.lower() not in only and pokeid not in only:
                continue

        disappear_timestamp = time.time() + poke.TimeTillHiddenMs \
            / 1000

        if args.china:
            (poke.Latitude, poke.Longitude) = \
                transform_from_wgs_to_gcj(Location(poke.Latitude,
                    poke.Longitude))

        pokemon_obj = {
            "lat": poke.Latitude,
            "lng": poke.Longitude,
            "disappear_time": disappear_timestamp,
            "id": poke.pokemon.PokemonId,
            "name": pokename
        }

        if poke.SpawnPointId not in pokemons:
            notifier.pokemon_found(pokemon_obj)

        pokemons[poke.SpawnPointId] = pokemon_obj

        print "Pokemon :", pokemon_obj

        print "PokespawnpointId: {}".format(poke.SpawnPointId)

def clear_stale_pokemons():
    current_time = time.time()

    for pokemon_key in pokemons.keys():
        pokemon = pokemons[pokemon_key]
        if current_time > pokemon['disappear_time']:
            print "[+] removing stale pokemon %s at %f, %f from list" % (
                pokemon['name'].encode('utf-8'), pokemon['lat'], pokemon['lng'])
            del pokemons[pokemon_key]

if __name__ == '__main__':
    main()
