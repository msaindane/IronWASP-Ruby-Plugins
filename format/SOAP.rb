#Author: Manish Saindane
#License: MIT License - http://www.opensource.org/licenses/mit-license

include Iron
include System
include System::Text

class SOAP < FormatPlugin
  
    def ToXmlFromRequest(request)
        return ToXml(request.body_array)
    end
    
    def ToXmlFromResponse(response)
        return ToXml(response.body_array)
    end
    
    def ToXml(object_array)
        xml = Encoding.UTF8.GetString(object_array)
        mod_xml = modify_soap_tags(xml)
        return mod_xml
    end
    
    def ToRequestFromXml(request, xml)
        mod_xml = restore_soap_tags(xml)
        request.body_string = mod_xml
        return request
    end

    def ToResponseFromXml(response, xml)
        mod_xml = restore_soap_tags(xml)
        response.body_string = mod_xml
        return response
    end

    def ToObject(xml)
        mod_xml = restore_soap_tags(xml)
        return Encoding.UTF8.GetBytes(mod_xml)
    end

    def modify_soap_tags(xml)
        # xmlns has to be modified to avoid error [The prefix '' cannot be redefined from '' to 'XYZ' 
        # within the same start element tag.]
        #
        # We also replace and tag with the format <x:y> to <x_IRONWASP_y> 
        # as XML errors out if it comes across tags with a ':' in the name.
        return xml.gsub(' xmlns="', ' xmlns_IRONWASP="').gsub(/<(.*?):/, '<\1_IRONWASP_')
    end

    def restore_soap_tags(xml)
        # revert changes made with the modify_soap_tags method
        return xml.gsub(' xmlns_IRONWASP="', ' xmlns="').gsub('_IRONWASP_', ':')
    end
end

p = SOAP.new
p.Name = "SOAP"
p.Description = "A modified version of the XML Format plugin to handle SOAP XML used to enable setting Injection points"
FormatPlugin.add(p)