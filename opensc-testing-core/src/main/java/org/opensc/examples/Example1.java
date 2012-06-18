/* 
 * Example1.java Copyright (C) 2012 This file is part of OpenSC project
 * 
 * This software is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As a special exception, if you link this library with other files to
 * produce an executable, this library does not by itself cause the
 * resulting executable to be covered by the GNU General Public License.
 * This exception does not however invalidate any other reasons why the
 * executable file might be covered by the GNU General Public License.
 * 
 * Authors:: Alejandro Díaz Torres (mailto:adiaz@emergya.com)
 * Authors:: Alejandro Díaz Torres (mailto:aledt84@gmail.com)
 */
package org.opensc.examples;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.util.Enumeration;

import org.opensc.testing.SecurityUtils;

/**
 * Java SunPKCS11 sample for ePass token
 * This sample will load SunPKCS#11 provider, enumerate the certificates
 * in the token and use selected certificate to sign and verify context string.
 * 
 * @author adiaz - separate SecutityUtils.java
 */
public class Example1 {

    private static KeyStore keyStore;
    
    public static void main(String args[]) {
	        System.out.println("ePass PCKS#11 Test");
	        try {
	
	            //Acquire user PIN            
	            InputStreamReader reader = new InputStreamReader(System.in);
	            BufferedReader input = new BufferedReader(reader);
	            System.out.print("Please input token user PIN: ");
	            String userPIN = input.readLine();
	            char[] pin = userPIN.toCharArray();
	
	            //Initialize Key Store
	            keyStore = SecurityUtils.getInitializedKeyStore(userPIN);
	
	            //Enumerate certificates in the token
	            int numCerts = 0;
	            String alias = "";
	            Enumeration<String> aliasesEnum = keyStore.aliases();
	            while (aliasesEnum.hasMoreElements()) {
	                alias = (String) aliasesEnum.nextElement();
	                System.out.println(numCerts + ") " + alias);
	                numCerts++;
	            }
	
	            if (numCerts <= 0) {
	                System.out.println("Cannot find the digital certificate in the token.");
	                System.exit(1);
	            }
	
	            if (numCerts > 1) {
	                System.in.read();
	            }
	
	            String dataToSign = "OpenSC http://www.opensc-project.org/opensc";
	            System.out.println("Source data for signature: " + dataToSign);
	            
	            if (SecurityUtils.simpleSign(dataToSign.getBytes(), alias, pin, keyStore)) {
	                System.out.println("Signature verification Succeeded!");
	            } else {
	                System.out.println("Signature verification FAILED!");
	            }
	        
	        } catch (Exception e) {
	            e.printStackTrace();
	        }

    	}

}