from zenpacket.interceptor import Interceptor
from zenpacket.template import Template

template = Template()
interceptor = Interceptor(template)
interceptor.intercept()