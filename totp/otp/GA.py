import time
import pyotp
import logging
import exceptions

class UserSecretError(exceptions.Exception):
    def __init__(self, message):
        exceptions.Exception.__init__(self, message)
        logger.debug('!UserSecretError: %s' % message)

class UserSecret:
    def __init__(self, secret):
        # This should immediately tell us if there are problems with the
        # secret as read from the file.
        try:
            self.totp = pyotp.TOTP(secret.secret)

            self.token     = self.totp.now()
            self.timestamp = int(time.time())

        except Exception, ex:
            raise UserSecretError('Failed to generate totp: %s' % str(ex))

        self.rate_limit_times = secret.rate_limit_times
	self.rate_limit_seconds = secret.rate_limit_seconds
        self.window_size    = 0

    def get_token_at(self, timestamp):
        return self.totp.at(timestamp)

