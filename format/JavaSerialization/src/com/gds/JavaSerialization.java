// Author: Manish Saindane (manish [-at-] andlabs.org)
// License: MIT License - http://www.opensource.org/licenses/mit-license

package com.gds;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.core.util.Base64Encoder;


public class JavaSerialization {
	
	/* This method accepts a Java object as a Byte array and converts it
	 * to an XML string
	 */ 
	public static String objToXml(byte[] brr) throws IOException, ClassNotFoundException{
		String xml = null;
		ByteArrayInputStream bis = new ByteArrayInputStream(brr, 0, brr.length);
		ObjectInputStream ois = new ObjectInputStream(bis);
		Object obj = ois.readObject();
		XStream xs = new XStream();
		xml = xs.toXML(obj);
		return xml;
	}
	
	/* This method accepts an XML string and converts it
	 * to an a Java object byte array
	 */ 
	public static byte[] xmlToObject(String xml) throws IOException {
		XStream xs = new XStream();
		Object obj = xs.fromXML(xml);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);
		oos.writeObject(obj);
		byte[] buff = bos.toByteArray();
		return buff;
	}
	
	/* This program is to convert Java Serialized Objects to XML and back.
	 * 
	 * USAGE: java -jar JavaSerialization.jar <base64 string> <xml | java>
	 * The last option can be either:
	 * xml -> to convert a Java Serialized Object to XML
	 * java -> to conver an XML to Java Serialized Object
	 * 
	 * REMEMBER: The first input is always a Base64 string. This can be a Java Serialized Object
	 * converted to a Base64 string or XML converted to a Base64 string
	 */ 
	public static void main(String [] args) throws IOException, ClassNotFoundException {
		String usage = "java -jar JavaSerialization.jar <base64 string> <xml | java>";
		
		if (args.length < 2) {
			System.out.println("ERROR: Wrong Options");
			System.out.println(usage);
		} else {
			String payload = args[0].trim();
			String opt = args[1].trim();
			Base64Encoder encoder = new Base64Encoder();
			byte[] msg = encoder.decode(payload);
			
			
			if (opt.equalsIgnoreCase("java")) {
				byte[] bf = xmlToObject(new String(msg));
				String out = encoder.encode(bf);
				System.out.println(out.replaceAll("\\n", ""));
				System.exit(0);
			} else if(opt.equalsIgnoreCase("xml")) {
				String xml = objToXml(msg);
				System.out.println(xml);
				System.exit(0);
			} else {
				System.out.println("ERROR: Wrong Options");
				System.out.println(usage);
			}
		}
	}

}
