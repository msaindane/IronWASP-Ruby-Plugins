# Author: Manish Saindane
# License: MIT License - http://www.opensource.org/licenses/mit-license

include IronWASP
include System::Xml
include System::Text
include System::IO

class JavaSerialization < FormatPlugin

    @@root_path =  Config.path.gsub("\\", '/') + '/plugins/format/JavaSerialization/'
    jars = []
    Dir[@@root_path + 'lib/clientlibs/*.jar'].each {|file| jars << file}
    Dir[@@root_path + 'lib/java/*.jar'].each {|file| jars << file }
    @@path = "\"" + jars.join('";"') + "\""
	
	@@env_set_up = false

	def SetUpEnv()
		#Check if JavaSerialization, lib/clientlibs and lib/java folders are created. If they are not created then create these directories from code
		#Check if lib/clientlibs folder contains the three files required for it to work, if not make note of it
		#Check if lib/java folder contains the three files required for it to work, if not make note of it
		
		#Ask user to set things up

		lib_path = Config.path + "\\plugins\\format\\JavaSerialization\\lib\\java"
		client_lib_path = Config.path + "\\plugins\\format\\JavaSerialization\\lib\\clientlibs"

		msg = %(
		Inorder to provide the Java Serialized Object Support to IronWASP make sure the following requirements are met.

		<i<h>>Environment<i</h>>
		Please make sure you have <i<cb>>Java v1.6 or higher<i</cb>> installed on your machine otherwise Java Serialized Object support does not work.

		<i<h>>Libraries<i</h>>
		You need to download three jar files inorder to set-up Java Serialized Objects Support.
		These files are available from <i<cg>>https://github.com/msaindane/files<i</cg>>

		Copy these three files to <i<cg>>#{lib_path}<i</cg>>

		<i<h>>Application Class Libraries<i</h>>
		Inorder to Serialize and DeSerialize an object the class library used by the application must be placed in <i<cg>>#{client_lib_path}<i</cg>>

		If you have met the above requirements then click on the <i<b>>Yes<i</b>> button.
		If you do not wish to use Java Serialized Object support click on the <i<b>>No<i</b>> button.

		For any queries please contact <i<cb>>msaindane@gdssecurity.com<i</cb>> or <i<cb>>@msaindane<i</cb>>

		)
		if !@@env_set_up
		  @@env_set_up = AskUser.for_bool("Java Serialized Object Support Configuration", msg)
		end
	end
	
    #Override the ToXmlFromRequest method of the base class with custom functionlity. Convert RequestBody in to Xml String and return it
    def ToXmlFromRequest(req)
        SetUpEnv()
		barr = req.body_array
        return ToXml(barr)
    end

    #Override the ToXmlFromResponse method of the base class with custom functionlity. Convert ResponseBody in to Xml String and return it
    def ToXmlFromResponse(res)
        SetUpEnv()
		barr = res.body_array
        return ToXml(barr)
    end

    #Override the ToXml method of the base class with custom functionlity. Convert ByteArray in to Xml String and return it
    def ToXml(obj)
        b64bodystr = Tools.base64_encode_byte_array(obj)
        xml = java_to_xml(b64bodystr)
        return indent_xml(xml)
    end

    #Override the ToRequestFromXml method of the base class with custom functionlity. Update Request based on Xml String input and return it
    def ToRequestFromXml(req, xml)
        SetUpEnv()
		b64obj = ToObject(xml)
        req.binary_body_string = b64obj
        return req
    end

    #Override the ToResponseFromXml method of the base class with custom functionlity. Update Response based on Xml String input and return it
    def ToResponseFromXml(res, xml)
        SetUpEnv()
		b64obj = ToObject(xml)
        res.binary_body_string = b64obj
        return res
    end

    #Override the ToObject method of the base class with custom functionlity. Convert the XmlString in to an Object and return it as ByteArray
    def ToObject(xml)
        b64obj = xml_to_java(Tools.base64_encode(xml))
    end

    def java_to_xml(b64str)
        b64str = b64str.gsub("\n", "")
        str = "java -cp #{@@path} com.gds.JavaSerialization #{b64str} xml"
        #Tools.trace('JAVA <-> XML', str)
        out = %x[#{str}]
        #Tools.trace('JAVA <-> XML Output', out)
        return out
    end

    def xml_to_java(b64str)
        b64str = b64str.gsub("\n", "")
        str = "java -cp #{@@path} com.gds.JavaSerialization #{b64str} java"
        # Tools.trace('XML <-> JAVA', str)
        out = %x[#{str}]
        # Tools.trace('XML <-> JAVA Output', out)
        return out
    end

    def indent_xml(xml)
        doc = XmlDocument.new
        doc.load_xml(xml)
        ms = MemoryStream.new
        writer = XmlTextWriter.new(ms, nil)
        writer.formatting = Formatting.Indented
        doc.save(writer)
        writer.flush
        xmlout = Encoding.UTF8.GetString(ms.to_array)
        ms.close
        return xmlout
    end

end

p = JavaSerialization.new
p.name = "JavaSerialization"
p.description = "Plugin to handle Java Serialized Object format in request and responses."
FormatPlugin.add(p)
