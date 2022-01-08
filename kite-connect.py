import logging
from pyotp import TOTP
from kiteconnect import KiteConnect
import asyncio
import time
import nest_asyncio
from urllib.parse import urlparse , parse_qs
from pyppeteer import launch
from datetime import datetime, timedelta;

apiKey = 'yourApiKey'
apiSecret = 'yourApiSecret'
totpSecret = 'yourTotpSecret' # this is the secret used to generate the 6 digit auth token using google authenticator API.
userId = 'yourUserId'
userPass = 'yourUserPass'


#silencing some unecessary logs
logging.getLogger('asyncio').setLevel(logging.WARNING)
logging.getLogger('asyncio.coroutines').setLevel(logging.WARNING)
logging.getLogger('websockets').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

nest_asyncio.apply()

async def takeScreenshot(page, count):
    screenshotFileName = 'screenshot' + str(count) + '.png';
    if(enableScreenshotting):
        logging.debug('Taking Screenshot ' + str(count))
        await page.screenshot({'path': screenshotFileName})

def getAuthToken():
    totp = TOTP(totpSecret)
    return totp.now()

def getLoginUrl(kite):
    return kite.login_url();

def getRequestAccessTokenFromUrl(url):
    return parse_qs(urlparse(url).query)['request_token'][0]

def getAccessToken(kite):
    async def main():
        logging.debug('Launching headless browser to fetch requestToken');
        browser = await launch()
        page = await browser.newPage()
        await page.goto(getLoginUrl(kite));
        time.sleep(2)
        await takeScreenshot(page,1)
        logging.debug('Entering userId = ' + userId + ' and password = ' + userPass );
        await page.type('input#userid', userId, { 'delay': 50 });
        await page.type('input#password', userPass, { 'delay': 50 });
        await page.click('button.button-orange.wide');
        await takeScreenshot(page,2)
        time.sleep(2)
        authOtp = getAuthToken()
        logging.debug('Entering auth otp = ' + authOtp);
        await takeScreenshot(page,3)
        await page.type('input#totp', authOtp, { 'delay': 50 });
        await takeScreenshot(page,4)
        await page.click('button.button-orange.wide');
        response = await page.waitForNavigation()
        accessToken = getRequestAccessTokenFromUrl(response.url)
        logging.debug('Generated request access token = '+ accessToken)
        await takeScreenshot(page,5)
        # Logs show up in the browser's devtools
        await browser.close()
        return accessToken
    return asyncio.get_event_loop().run_until_complete(main())

def getAuthenticatedKite():
    logging.basicConfig(level=logging.INFO)
    kite = KiteConnect(api_key=apiKey)
    accessToken = getAccessToken(kite)
    data = kite.generate_session(accessToken, api_secret=apiSecret)
    kite.set_access_token(data["access_token"])
    logging.basicConfig(level=logging.INFO)
    return kite

def getInstruments(kite):
    logging.debug('Fetching all instruments');
    instruments = {} 
    for i in kite.instruments():
        key = i['exchange']+':'+i['tradingsymbol']
        if key not in instruments:
            instruments[key] = []
        instruments[key].append(i);
    return instruments;

kite = getAuthenticatedKite()
instruments = getInstruments(kite);


