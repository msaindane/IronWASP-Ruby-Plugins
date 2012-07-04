#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license

include IronWASP

class CookieAnalysis < PassivePlugin

  def GetInstance
  	p = CookieAnalysis.new
		p.name = "CookieAnalysis"
		p.version = "0.2"
		p.description = "This plugin analyses cookies set by server responses and reports cookies missing 'HTTPOnly' flag and if the response is over SSL then whether the 'secure' flag is set and also alerts the user if it may contain sensitive information."
		#p.calling_state = PluginCallingState.before_interception
		p.works_on = PluginWorksOn.response
		return p
  end
  
  def Check(ironsess, results)
    if ironsess.Response.Headers.has("Set-Cookie")
      cookie_jar = ironsess.Response.set_cookies
      cookie_jar.each do |cookie|
        check_httponly(ironsess, results, cookie)
        check_secure(ironsess, results, cookie) if ironsess.Request.ssl
        check_sensitive_info(ironsess, results, cookie)
      end
    end
  end
  
  def check_httponly(ironsess, results, cookie)
    flag = cookie.http_only
    if !flag
        signature = "cookie|#{cookie.name}|httponly"
        if is_signature_unique(ironsess.Request.host, PluginResultType.vulnerability, signature)
	        plugin_result = PluginResult.new(ironsess.Request.host)
	        plugin_result.title = "Cookie #{cookie.name} missing the HttpOnly flag"
	        plugin_result.summary = "The HttpOnly flag was missing on the cookie: #{cookie.name}. This may allow an attacker to get the cookie information using XSS attacks."
	        plugin_result.triggers.add("",ironsess.Request, cookie.full_string, ironsess.Response)
	        plugin_result.signature = signature
	        plugin_result.result_type = PluginResultType.vulnerability
	        plugin_result.confidence = PluginResultConfidence.high
	        plugin_result.severity = PluginResultSeverity.medium
	        results.add(plugin_result)
       	end
    end
  end
  
  def check_secure(ironsess, results, cookie)
    flag = cookie.secure
    if !flag
    	signature = "cookie|#{cookie.name}|secure"
    	if is_signature_unique(ironsess.Request.host, PluginResultType.vulnerability, signature)
        plugin_result = PluginResult.new(ironsess.Request.host)
        plugin_result.title = "Cookie #{cookie.name} missing the Secure flag"
        plugin_result.summary = "The Secure flag was missing on the cookie: #{cookie.name}. This may allow the cookie to be transferred over an insecure channel."
        plugin_result.triggers.add("",ironsess.Request, cookie.full_string, ironsess.Response)
        plugin_result.signature = signature
        plugin_result.result_type = PluginResultType.vulnerability
        plugin_result.severity = PluginResultSeverity.medium
        plugin_result.confidence = PluginResultConfidence.high
        results.add(plugin_result)
    	end
    end
  end
  
  def check_sensitive_info(ironsess, results, cookie)
    r = Regexp.new('user|pass|uid|pwd|admin|attempt|retr|login|auth|secure|limit', Regexp::IGNORECASE)
    if r =~ cookie.value or r =~ cookie.name
      signature = "cookie|#{cookie.name}|sensitive info"
      if is_signature_unique(ironsess.Request.host, PluginResultType.test_lead, signature)
        plugin_result = PluginResult.new(ironsess.Request.host)
        plugin_result.title = "Cookie #{cookie.name} may contain sensitive information"
        plugin_result.summary = "The cookie: #{cookie.name} might contain sensitive information which could be easily accessed or modified to exploit the web application."
        plugin_result.triggers.add("",ironsess.Request, cookie.full_string, ironsess.Response)
        plugin_result.signature = signature
        plugin_result.result_type = PluginResultType.test_lead
        plugin_result.severity = PluginResultSeverity.medium
        plugin_result.confidence = PluginResultConfidence.low
        results.add(plugin_result)
      end
    end
  end
end

p = CookieAnalysis.new
PassivePlugin.add(p.get_instance)
