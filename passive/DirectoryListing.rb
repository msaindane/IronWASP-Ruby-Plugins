#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license

include IronWASP

class DirListing < PassivePlugin

    def Check(sess, results)
        res = sess.response
        matches_found = dir_listing_check(res)
        report_vuln(sess, results, matches_found) unless matches_found.empty?
    end

    def dir_listing_check(res)
        regexs = ['<title>Index of /',
        			'Parent Directory</a>',
        			'Directory Listing for',
        			'<TITLE>Folder Listing',
        			'<table summary="Directory Listing" ',
        			'- Browsing directory ',
        			'[To Parent Directory]']
        ret_arr = []

        regexs.each do |regex|
        	escaped_regex = Regexp.escape(regex)
        	match = /#{escaped_regex}/im.match(res.body_string)
        	ret_arr = match.to_a unless match.nil?
        end

        return ret_arr
    end

    def report_vuln(sess, results, matches_found)
    	req = sess.request
    	res = sess.response
        signature = "DirListing|#{req.url_path}"

        if is_signature_unique(ironsess.Request.host, PluginResultType.vulnerability, signature)
            plugin_result = PluginResult.new(req.host)
        	plugin_result.title = "Directory Listing at : #{req.url_path}"
        	plugin_result.summary = "A directory listing vulnerability was found at <i<hlo>>#{req.url_path}<i</hlo>><i<br>>"+
            "A directory listing provides an attacker with the complete index of all the resources located"+
            "inside of the directory. The specific risks and consequences vary depending"+
            "on which files are listed and accessible.<i<br>>"+
            "<i<cb>><i<b>>References:<i</b>><i</cb>><i<br>>CWE-548: Information Exposure Through Directory Listing"
            plugin_result.triggers.add("", req, matches_found.join(','), res)
        	plugin_result.severity = PluginResultSeverity.medium
        	plugin_result.confidence = PluginResultConfidence.medium
        	plugin_result.signature = signature
        	results.add(plugin_result)
        end
    end
end

p = DirListing.new
p.name = "Directory Listing"
p.description = "Identifies directory listing issuses in the website being tested."
#When should this plugin be called. Possible values - before_interception, after_interception, both
#p.calling_state = PluginCallingState.before_interception
#On what should this plugin run. Possible values - request, response, both, offline. offline is the default value, it is also the recommended value if you are not going to perform any changes in the request/response
p.works_on = PluginWorksOn.response
PassivePlugin.add(p)
