#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license
 
include Iron

class WebServerAnalysis < PassivePlugin

  def Check(ironsess, results)
    banner=""
    if ironsess.Response.headers.has("Server")
      banner = ironsess.Response.headers.get("Server")
      if banner.length > 0
        report_server_name(ironsess, results, banner)
        check_version(ironsess, results, banner)
      end
    end
  end
  
  def report_server_name(ironsess, results, banner)
    plugin_result = PluginResult.new(ironsess.Request.host)
    plugin_result.title = "Runs on #{banner}"
    plugin_result.summary = "The Web Server returned this banner in its response headers - #{banner}"
    plugin_result.triggers.add("",ironsess.Request,banner,ironsess.Response)
    plugin_result.result_type = PluginResultType.information
    plugin_result.severity = PluginResultSeverity.low
	plugin_result.confidence = PluginResultConfidence.high
    plugin_result.signature = "WebServerAnalysis|information|serverheader|#{ironsess.Request.host}|#{banner}"
    results.add(plugin_result)
  end
  
  def check_version(ironsess, results, banner)
    /(.+?)\/([\d\.\-]+)/.match(banner)
    if $2 != nil
      report_version_found(ironsess, results, banner, $2)
      check_if_version_old(ironsess, results, banner, $1, $2)
    end
  end
  
  def report_version_found(ironsess, results, banner, version)
    plugin_result = PluginResult.new(ironsess.Request.host)
    plugin_result.title = "Server leaks version number"
    plugin_result.summary = "The Web Server's banner contains the version number of the server - #{banner}"
    plugin_result.triggers.add('',ironsess.Request, version, ironsess.Response)
    plugin_result.result_type = PluginResultType.vulnerability
    plugin_result.confidence = PluginResultConfidence.high
    plugin_result.severity = PluginResultSeverity.low
    plugin_result.signature = "WebServerAnalysis|vulnerability|low|serverversion|#{ironsess.Request.Host}|#{banner}"
    results.add(plugin_result)
  end
  
  def check_if_version_old(ironsess, results, banner, name, version)
    version_parts = version.split(".")
    if (name.casecmp "Apache") == 0
      if version_parts[0].to_i == 1
        title = "Deprecated version of Apache used (#{version})"
        summary = "The version of Apache server as per the banner is deprecated and is not supported anymore. (#{version})"
        report_vulnerable_version(ironsess, results, title, summary, banner, name, PluginResultSeverity.high, PluginResultConfidence.high)
      end
    elsif (name.casecmp "IIS") == 0
      if version_parts[0].to_i < 5
        title = "Deprecated version of IIS used (#{version})"
        summary = "The version of IIS server as per the banner is deprecated and is not supported anymore. (#{version})"
        report_vulnerable_version(ironsess, results, title, summary, banner, name, PluginResultSeverity.high, PluginResultConfidence.high)
      elsif version_parts[0].to_i == 5 && version_parts[1].to_i == 0
        title = "Vulnerable version of IIS used (#{version})"
        summary = "The version of IIS server as per the banner is outdated and suffers from multiple severe vulerabilities. (#{version})"
        report_vulnerable_version(ironsess, results, title, summary, banner, name, PluginResultSeverity.high, PluginResultConfidence.high)
      end
    end
  end
  
  def report_vulnerable_version(ironsess, results, title, summary, banner, name, severity, confidence)
    plugin_result = PluginResult.new(ironsess.Request.Host)
    plugin_result.title = title
    plugin_result.summary = summary
    plugin_result.triggers.add('', ironsess.Request, banner, ironsess.Response)
    plugin_result.result_type = PluginResultType.vulnerability
    plugin_result.confidence = confidence
    plugin_result.severity = severity
    plugin_result.signature = "WebServerAnalysis|vulnerability|vulnerableversion|#{ironsess.Request.host}|#{banner}|#{title}"
    results.add(plugin_result)
  end
end

p = WebServerAnalysis.new
p.name = "Web Server Identification"
p.description = "This plugin analyzes the 'Server' header in the HTTP response and reports interesting information from it"
#p.calling_state = PluginCallingState.before_interception
p.works_on = PluginWorksOn.response
PassivePlugin.add(p)
