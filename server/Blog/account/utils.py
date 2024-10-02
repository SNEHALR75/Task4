from django.core.mail import send_mail
from threading import Thread




def async_send_email( subject, message, from_email, recipient_list ):
	thread = Thread( target=send_mail, kwargs={
			'subject':subject,
			'message':message,
			'from_email':from_email,
			'recipient_list':recipient_list
		}
	)
	thread.start()




















