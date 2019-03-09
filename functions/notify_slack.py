import os
import logging
import json
import boto3

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
SLACK_CHANNEL = os.environ['slackChannel']

SLACK_WEBHOOK_URL = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext'].decode(
    'utf-8')

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info("Message: " + str(message))

    region = message['region']
    pipeline_name = message['detail']['pipeline']
    state = message['detail']['state']

    if state == "STARTED":
        slack_message = {
            "channel": SLACK_CHANNEL,
            "attachments": [
                {
                    "pretext": "%sによるサーバーの更新が開始されました。" % (pipeline_name),
                    "color": "#04B404",
                    "title": "AWS CodePipeline",
                    "fields": [
                        {
                            "title": "%s" % (pipeline_name)
                        }
                    ],
                    "title_link": "https://%s.console.aws.amazon.com/codepipeline/home?region=%s#/view/%s" % (region, region, pipeline_name)
                }
            ]
        }
    elif state == "SUCCEEDED":
        slack_message = {
            'channel': SLACK_CHANNEL,
            'attachments': [
                {
                    "pretext": "%sによるサーバーの更新が正常に終了しました。" % (pipeline_name),
                    "color": "#0174DF",
                    "title": "AWS CodePipeline",
                    "fields": [
                        {
                            "title": "%s" % (pipeline_name)
                        }
                    ],
                    "title_link": "https://%s.console.aws.amazon.com/codepipeline/home?region=%s#/view/%s" % (region, region, pipeline_name)
                }
            ]
        }
    else:
        slack_message = {
            'channel': SLACK_CHANNEL,
            'attachments': [
                {
                    "pretext": "%sの実行中にエラーが発生しました。" % (pipeline_name),
                    "color": "#FF0040",
                    "title": "AWS CodePipeline",
                    "fields": [
                        {
                            "title": "%s" % (pipeline_name)
                        }
                    ],
                    "title_link": "https://%s.console.aws.amazon.com/codepipeline/home?region=%s#/view/%s" % (region, region, pipeline_name)
                }
            ]
        }

    request = Request(SLACK_WEBHOOK_URL, json.dumps(slack_message).encode('utf-8'))

    try:
        response = urlopen(request)
        response.read()
        logger.info("%sというメッセージを投稿しました。", slack_message['channel'])
    except HTTPError as e:
        logger.error("%sへのメッセージの投稿にエラーが発生しました。%d",e.reason,e.code)
    except URLError as e:
        logger.error("サーバーへの接続に失敗しました。%s", e.reason)

