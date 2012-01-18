#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license

include IronWASP

class BasicAuthentication < PassivePlugin
    def Check(ironsess, results)
        if ironsess.Response.headers.has('WWW-Authenticate') and !ironsess.Request.ssl
            auth_method = ironsess.Response.headers.get('WWW-Authenticate')
            report_basic_auth(ironsess, auth_method, results) if auth_method =~ /basic/i
        end
    end
    
    def report_basic_auth(ironsess, auth_method, results)
        plugin_result = PluginResult.new(ironsess.Request.host)
        plugin_result.title = "Insecure Basic Authentication used"
        plugin_result.summary = "The server uses Basic Authentication over insecure channel. Basic Authentication encodes the credentials using Base64 which can be easily decoded if captured over insecure channel."
        plugin_result.triggers.add('',ironsess.Request, auth_method, ironsess.Response)
        plugin_result.result_type = PluginResultType.vulnerability
        plugin_result.confidence = PluginResultConfidence.high
        plugin_result.severity = PluginResultSeverity.high
        plugin_result.signature = "BasicAuthentication|vulnerability|high|authorization|#{ironsess.Request.host}"
        results.add(plugin_result)
    end
end

p = BasicAuthentication.new
p.name = "Basic Auth Check"
p.description = "This plugin checks for the use of Basic Authentication over insecure channels."
p.works_on = PluginWorksOn.response
PassivePlugin.add(p)