package com.akamai.siem;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;


//import java.util.Base64;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;


public class MainTest {
	@Test
	public void testMain() throws Exception
	{				
		String testFile = "com/akamai/siem/test_dlrs.json";
		String responseFile = "com/akamai/siem/response.json";

		InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(testFile);
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		
		InputStream responseStream = this.getClass().getClassLoader().getResourceAsStream(responseFile);
		BufferedReader res = new BufferedReader(new InputStreamReader(responseStream));

		String dlrLine;
		String resLine= "";
		
		while ( ((dlrLine = reader.readLine()) != null) && ((resLine = res.readLine()) != null)) {
			JsonParser parser = new JsonParser();	
			JsonObject jObj = parser.parse(dlrLine).getAsJsonObject();
		 	JsonObject newJsonObj = Main.processData(jObj);
		 	System.out.println(newJsonObj);
		 	Assert.assertEquals(resLine.trim(), newJsonObj.toString().trim());
		}

		
		System.out.println("Done");
	}
}
