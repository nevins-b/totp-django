from django.db import models
from django.db.models import F
from django.conf import settings
import GA
import base64, os, time 
import qrcode
from StringIO import StringIO

# Create your models here.
class User(models.Model):
	username = models.CharField(max_length=255,unique=True)
	
	def save(self,*args, **kwargs):
		super(User, self).save(*args, **kwargs)
		if not Secret.objects.filter(userid=self).exists():
			self.get_secret()
			self.get_scratch_tokens()

	def get_secret(self):
		if not Secret.objects.filter(userid=self).exists():
			good_chars = base64._b32alphabet.values()
                        secret = ''
                        while len(secret) < 16:
                                rchar = os.urandom(1)
                                if rchar in good_chars:
                                        secret += rchar
                        Secret.objects.create(
                                userid=self,
                                secret = secret,
                                rate_limit_times = settings.RATE_LIMIT_TIMES,
                                rate_limit_seconds = settings.RATE_LIMIT_SECONDS,
                                window_size = settings.WINDOW_SIZE)
		return Secret.objects.get(userid=self)

	def get_scratch_tokens(self):	
		if not ScratchToken.objects.filter(userid=self).filter(used=False).exists():
			good_chars = '0123456789'
                        for i in xrange(settings.SCRATCH_TOKENS):
                                scratch_token = ''
                                while len(scratch_token) < 8:
                                        rchar = os.urandom(1)
                                        if rchar in good_chars:
                                                scratch_token += rchar
                                ScratchToken.objects.create(userid=self,used=False,token=scratch_token)
		return ScratchToken.objects.values_list('token', flat=True).filter(userid=self).filter(used=False)

	def verify_token(self,token):
		try:
			secret = GA.UserSecret(Secret.objects.get(userid=self))
		except Entry.DoesNotExist, ex:
			now = int(time.time())
			for timestamp in xrange(now, now-300, -30):
				Timestamp.objects.create(userid=self,success=False,timestamp=timestamp)
		previous_success = Timestamp.objects.values_list('timestamp',flat=True).filter(userid=self).filter(success=True).filter(timestamp__gt=F('timestamp') - ( 30 + (secret.window_size * 10 )))

		previous_failure = Timestamp.objects.values_list('timestamp',flat=True).filter(userid=self).filter(success=False).filter(timestamp__gt=F('timestamp') - 30 + secret.rate_limit_seconds )

		used_tokens = []
		for timestamp in previous_success:
			at_token = secret.get_token_at(timestamp)
			if at_token not in used_tokens:
                		used_tokens.append(at_token)
		for timestamp in previous_failure:
                        at_token = secret.get_token_at(timestamp)
                        if at_token not in used_tokens:
                                used_tokens.append(at_token)

		used_timestamp = secret.timestamp
		used_token     = secret.token

		if len(previous_failure) >= secret.rate_limit_times:
			 success = (False, 'Rate-limit reached, please try again later')
		else:
			if len(str(token)) > 8:
                		success = (False, 'Token is too long')
            		else:
				try:
                    			token = int(token)
                		except ValueError:
                    			success = (False, 'Token is not an integer')
                    			token = -1			
				if token > 999999:
					if token in ScratchToken.objects.values_list('token', flat=True).filter(userid=self).filter(used=False):
						success = (True, 'Scratch-token used')
						ScratchToken.objects.filter(userid=self).filter(token=token).update(used=True)
					else:
						success = (False, 'Scratch-token already or not valid') 
				elif token >=0:
					if token in used_tokens:
						success = (False, 'Token has already been used once')
					elif token == secret.token:
						success = (True, 'Valid token used')
					else:
						success = (False, 'Not a valid token')
						if secret.window_size > 0:
							# Possible issue here that if a valid token is found all previous ones are marked as used?
							start = secret.timestamp - ( secret.window_size * 10 )
							end   = secret.timestamp + ( secret.window_size * 10 ) + 1
							for timestamp in xrange(start, end, 10):
								at_token = secret.get_token_at(timestamp)
								if at_token == token:
									used_timestamp = timestamp
									used_token = token
									success = (True, 'Valid token within window size used')
									break	
				if success[0] == True:
					Timestamp.objects.create(userid=self,timestamp=used_timestamp,success=True)
				else:
					for ts in xrange(used_timestamp, used_timestamp-(secret.window_size*10), -30):
						Timestamp.objects.create(userid=self,timestamp=ts,success=False)
		return success
							
class Timestamp(models.Model):
	userid = models.ForeignKey('User')
	success = models.BooleanField()
	timestamp = models.IntegerField()
	class Meta:
		unique_together = (("userid", "timestamp"),)

class Secret(models.Model):
	userid = models.ForeignKey('User',unique=True)
	secret = models.CharField(max_length=255)
	rate_limit_times = models.IntegerField(default=3)
	rate_limit_seconds = models.IntegerField(default=30)
	window_size = models.IntegerField(default=0)
	
	def generate_qrcode(self):
		data = 'otpauth://totp/%s@%s?secret=%s' %(self.userid.username, settings.TOTP_DOMAIN, self.secret)
		qr = qrcode.QRCode(
            		version=1,
            		error_correction=qrcode.constants.ERROR_CORRECT_L,
            		box_size=5,
            		border=4)
		qr.add_data(data)
    		qr.make(fit=True)
    		img = qr.make_image()
		img.show()

class ScratchToken(models.Model):
	userid = models.ForeignKey('User')	
	token = models.IntegerField()
	used = models.BooleanField(default=False)
