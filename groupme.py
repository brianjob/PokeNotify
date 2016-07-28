import requests

api_url = 'https://api.groupme.com/v3/bots/post'

def send_message(text, bot_id):
  r = requests.post(api_url, data={'text': text, 'bot_id': bot_id})
  print r.text
