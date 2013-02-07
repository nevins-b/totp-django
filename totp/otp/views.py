# Create your views here.
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import IntegrityError
import logging
import time
from otp.models import User, Secret, ProvisioningKey

logger = logging.getLogger(__name__)

@csrf_exempt
def verify_user(request):
	logger.info('User Request from %s' % request.META['REMOTE_ADDR'])

	if request.method != 'POST':
		logger.warn('Non-Post from %s' % request.META['REMOTE_ADDR'])
		return HttpResponse(status=405)

	if not 'user' in request.POST or not 'hostname' in request.POST:
		logger.warn('Bad request from %s' % request.META['REMOTE_ADDR'])
		return HttpResponse(status=400)	

	if not User.objects.filter(username=request.POST['user']).exists():
		logger.warn('Bad request for %s from %s (%s)' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))
		return HttpResponse(status=400)

	logger.info('Good request for %s from %s (%s)' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))
	return HttpResponse(status=200)

@csrf_exempt
def verify_token(request):
	logger.info('Token Request from %s' % request.META['REMOTE_ADDR'])

	if request.method != 'POST':
		logger.warn('Non-Post from %s' % request.META['REMOTE_ADDR'])
                return HttpResponse(status=405)

	if not 'user' in request.POST or not 'hostname' in request.POST or not 'token' in request.POST:
		logger.warn('Bad request from %s' % request.META['REMOTE_ADDR'])	
                return HttpResponse(status=400 )

	if not User.objects.filter(username=request.POST['user']).exists():
		logger.warn('Bad request for %s from %s (%s)' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))
		return HttpResponse(status=400 )

	user = User.objects.get(username=request.POST['user'])
	result = user.verify_token(request.POST['token'])

	if not result[0]:
		logger.warn('Bad request for %s from %s (%s)' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))	
		return HttpResponse(result[1], status=400)

	logger.info('Good request for %s from %s (%s)' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))
	return HttpResponse(status=200)

@csrf_exempt
def provision_user(request):
	if request.method != 'POST':
                logger.warn('Non-Post from %s' % request.META['REMOTE_ADDR'])
                return HttpResponse(status=405)

        if not 'user' in request.POST or not 'hostname' in request.POST:
		return HttpResponse(status=400 )
	
	if User.objects.filter(username=request.POST['user']).exists():
		return HttpResponse(status=400 )
	try:
		user = User.objects.create(username=request.POST['user'])
	except IntegrityError, ex:
		return HttpResponse(status=400 )	
	
	pr_key = user.get_provisioning_key()
	return HttpResponse(pr_key.key, status=200)	

@csrf_exempt
def provision_secret(request):	
	if request.method != 'POST':
                logger.warn('Non-Post from %s' % request.META['REMOTE_ADDR'])
                return HttpResponse(status=405)

        if not 'user' in request.POST or not 'hostname' in request.POST or not 'key' in request.POST:
                return HttpResponse(1,status=400 )

        if not User.objects.filter(username=request.POST['user']).exists():
                return HttpResponse(2,status=400 )

	user = User.objects.get(username=request.POST['user'])

	if not user.verify_provisioning_key(request.POST['key']):
		return HttpResponse(4,status=400 )

	secret = user.get_secret()	
	return HttpResponse(secret.secret, status=200)

@csrf_exempt
def provision_scratch(request):
	if request.method != 'POST':
                logger.warn('Non-Post from %s' % request.META['REMOTE_ADDR'])
                return HttpResponse(status=405)

        if not 'user' in request.POST or not 'hostname' in request.POST or not 'key' in request.POST:
                return HttpResponse(status=400 )

        if not User.objects.filter(username=request.POST['user']).exists():
                return HttpResponse(status=400 )

        user = User.objects.get(username=request.POST['user'])
	
	if not user.has_secret():
		return HttpResponse(status=400 )
	
	if not user.verify_provisioning_key(request.POST['key']):
                return HttpResponse(status=400 )

	tokens = '\n'.join(str(x) for x in user.get_scratch_tokens())
	return HttpResponse(tokens, status=200)	
