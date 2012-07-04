#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license

include IronWASP

class CrossDomainXmlPolicyAnalysis < PassivePlugin
    
    def GetInstance
	    p = CrossDomainXmlPolicyAnalysis.new
		p.name = "Cross-domain XML policy analysis"
		p.version = "0.2"
		p.description = "This plugin analyzes the cross-domain policy for the web server and reports vulnerabilities."
		#p.calling_state = PluginCallingState.before_interception
		p.works_on = PluginWorksOn.response
		return p
    end
    
    def Check(ironsess, results)
        if ironsess.Request.url =~ /crossdomain.xml/i and ironsess.Response.code == 200
            check_allowed_domains(ironsess, results)
        end
    end
    
    def check_allowed_domains(ironsess, results)
        url = ironsess.Request.url
        bs = ironsess.Response.body_string
        xml_doc = HTML.new(bs)
        allowed_domain_tags = xml_doc.get_nodes('allow-access-from', 'domain')
        unless allowed_domain_tags.nil?
            allowed_domain_tags.each do |node|
                domain_value = node.get_attribute_value('domain', ''.to_clr_string)
                report_allowed_domains(ironsess, node.outer_html, results) if domain_value =~ /^\*$/
                if ironsess.Request.ssl
                    secure_flag = node.get_attribute_value('secure', ''.to_clr_string)
                    report_secure_flag(ironsess, node.outer_html, results) if secure_flag =~ /false/
                end
            end
        end
    end
    
    def report_allowed_domains(ironsess, node, results)
      signature = "high|cross-domain-policy|open domain|#ironsess.Request.url_path|#{node}"
      if is_signature_unique(ironsess.Request.host, PluginResultType.vulnerability, signature)
        plugin_result = PluginResult.new(ironsess.Request.host)
        plugin_result.title = "Wildcard domain set on Cross-domain policy"
        plugin_result.summary = "Setting wildcard (*) domains would allow access to documents originating from any domain."
        plugin_result.triggers.add('',ironsess.Request, node, ironsess.Response)
        plugin_result.result_type = PluginResultType.vulnerability
        plugin_result.confidence = PluginResultConfidence.high
        plugin_result.severity = PluginResultSeverity.high
        plugin_result.signature = signature
        results.add(plugin_result)
      end
    end
    
    def report_secure_flag(ironsess, node, results)
      signature = "high|cross-domain-policy|secure flag|#ironsess.Request.url_path|#{node}"
      if is_signature_unique(ironsess.Request.host, PluginResultType.vulnerability, signature)
        plugin_result = PluginResult.new(ironsess.Request.host)
        plugin_result.title = "Secure flag set to false on Cross-domain policy"
        plugin_result.summary = "The web application permits SWF files on a non-HTTPS server to load data from this HTTPS server. Setting the secure attribute to false could compromise the security offered by HTTPS. In particular, setting this attribute to false opens secure content to snooping and spoofing attacks."
        plugin_result.triggers.add('',ironsess.Request, node, ironsess.Response)
        plugin_result.result_type = PluginResultType.vulnerability
        plugin_result.confidence = PluginResultConfidence.high
        plugin_result.severity = PluginResultSeverity.high
        plugin_result.signature = signature
        results.add(plugin_result)
      end
    end
end

p = CrossDomainXmlPolicyAnalysis.new
PassivePlugin.add(p.get_instance)