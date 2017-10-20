package com.akamai.siem;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import org.junit.Assert;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;


public class ParseTest {
	
	
	@Test
	public void testParserGeneric() throws Exception
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
		 	Assert.assertEquals(resLine.trim(), newJsonObj.toString().trim());
		}
	}
	
	@Test
	public void dlrWithMultipleRuleID() throws Exception{
		
		String testFile = "com/akamai/siem/multipleRulesDLR.json";
		String responseFile = "com/akamai/siem/multipleRulesResponse.json";

		InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(testFile);
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		
		InputStream responseStream = this.getClass().getClassLoader().getResourceAsStream(responseFile);
		BufferedReader res = new BufferedReader(new InputStreamReader(responseStream));

		String dlrLine = reader.readLine();
		String resLine = res.readLine();
		
		JsonParser parser = new JsonParser();	
		JsonObject jObj = parser.parse(dlrLine).getAsJsonObject();
	 	JsonObject newJsonObj = Main.processData(jObj);
	 	Assert.assertEquals(resLine.trim(), newJsonObj.toString().trim());
		
	}
	
	
	@Test
	public void decodingIssueKSD13842() throws Exception{
		
		String testFile = "com/akamai/siem/decodingIssueKSD13842.json";
		String responseFile = "com/akamai/siem/decodingIssueKSD13842Response.json";

		InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(testFile);
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		
		InputStream responseStream = this.getClass().getClassLoader().getResourceAsStream(responseFile);
		BufferedReader res = new BufferedReader(new InputStreamReader(responseStream));

		String dlrLine = reader.readLine();
		String resLine = res.readLine();
		
		JsonParser parser = new JsonParser();	
		JsonObject jObj = parser.parse(dlrLine).getAsJsonObject();
	 	JsonObject newJsonObj = Main.processData(jObj);
	 
	 	byte[] arrayRes = resLine.trim().getBytes();
	 	byte[] arrayExp = newJsonObj.toString().getBytes(); 			
	 	Assert.assertArrayEquals(arrayRes, arrayExp);
	
		
	}
	
	@Test
	public void decodingWithPlus() throws Exception{
		
		String testFile = "com/akamai/siem/decodingIssuePlusDLR.json";
		String responseFile = "com/akamai/siem/decodingIssuePlusResponse.json";

		InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(testFile);
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		
		InputStream responseStream = this.getClass().getClassLoader().getResourceAsStream(responseFile);
		BufferedReader res = new BufferedReader(new InputStreamReader(responseStream));

		String dlrLine = reader.readLine();
		String resLine = res.readLine();
		
		JsonParser parser = new JsonParser();	
		JsonObject jObj = parser.parse(dlrLine).getAsJsonObject();
	 	JsonObject newJsonObj = Main.processData(jObj);
	 	Assert.assertEquals(resLine.trim(), newJsonObj.toString().trim());
		
		
		
	}
}
