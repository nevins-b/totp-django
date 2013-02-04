# Create your views here.
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import logging
from otp.models import User

logger = logging.getLogger(__name__)

@csrf_exempt
def verify_user(request):
	logger.info('verify-user: Request from %s' % request.META['REMOTE_ADDR'])
	if request.method != 'POST':
		logger.warn('verify-user: Non-Post from %s' % request.META['REMOTE_ADDR'])
		return HttpResponse("Only Post Accepted!", status=405)
	if not request.POST['user'] or not request.POST['mode'] or not request.POST['hostname']:
		logger.warn('verify-user: Bad request from %s' % request.META['REMOTE_ADDR'])
		return HttpResponse("Required information not provided", status=400)	
	if not User.objects.filter(username=request.POST['user']).exists():
		logger.warn('verify-user:: Bad request for %s from %s as %s' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))
		return HttpResponse("User not found!",status=400)
	logger.info('verify-user: Good request for %s from %s as %s' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))
	return HttpResponse("OK", status=200)

@csrf_exempt
def verify_token(request):
	logger.info('verify-token: Request from %s' % request.META['REMOTE_ADDR'])
	if request.method != 'POST':
		logger.warn('verify-token: Non-Post from %s' % request.META['REMOTE_ADDR'])
                return HttpResponse("Only Post Accepted!", status=405)
	if not request.POST['user'] or not request.POST['mode'] or not request.POST['hostname'] or not request.POST['token']:
		logger.warn('verify-token: Bad request from %s' % request.META['REMOTE_ADDR'])	
                return HttpResponse("Required information not provided", status=400 )
	if not User.objects.filter(username=request.POST['user']).exists():
		logger.warn('verify-token:: Bad request for %s from %s as %s' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))
		return HttpResponse("User not found!", status=400 )
	user = User.objects.get(username=request.POST['user'])
	result = user.verify_token(request.POST['token'])
	if not result[0]:
		logger.warn('verify-token: Bad request for %s from %s as %s' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))	
		return HttpResponse(result[1], status=400)
	logger.info('verify-token: Good request for %s from %s as %s' % (request.POST['user'], request.META['REMOTE_ADDR'], request.POST['hostname']))
	return HttpResponse("OK", status=200)
