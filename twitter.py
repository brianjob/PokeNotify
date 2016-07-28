import os
import tweepy

auth = tweepy.OAuthHandler(os.environ['TWITTER_CONSUMER_KEY'], os.environ['TWITTER_CONSUMER_SECRET'])
auth.set_access_token(os.environ['TWITTER_ACCESS_TOKEN'], os.environ['TWITTER_ACCESS_TOKEN_SECRET'])
api = tweepy.API(auth)

def tweet(message):
  print 'tweeting {}'.format(message)
  try:
    api.update_status(message)
  except tweepy.error.TweepError as e:
    print e
