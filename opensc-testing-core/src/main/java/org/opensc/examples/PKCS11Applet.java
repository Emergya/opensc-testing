/* 
 * PKCS11Applet.java Copyright (C) 2012 This file is part of OpenSC project
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

import java.applet.Applet;
import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Graphics;
import java.awt.GridLayout;
import java.awt.Label;
import java.awt.Panel;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.opensc.testing.SecurityUtils;

/**
 * Example applet for {@link SecurityUtils} use. Simple PKCS#11 sign OpenSC based 
 * 
 * @author adiaz
 * 
 * @see SecurityUtils
 *
 */
public class PKCS11Applet extends Applet  implements ActionListener{
	
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
		// Gui widgets
		TextField pinText, certText, textText;
		Button goButton, signButton;
		TextArea outText;
		protected Map<Integer, String> aliasesMap;
		
		// program variables
		String pin, textToSign, sign, verified;
		PrivateKey privateKey;
		X509Certificate certificate;
		KeyStore myStore;
		
		Set<String> errors = new HashSet<String>();
		
		public void init() {
			makeGui();
		} // init
		
		private void logException (Exception e){
			errors.add(e.getLocalizedMessage());
			if(e.getCause() != null){
				errors.add("Cause: " + e.getCause().getLocalizedMessage());
			}
		}
		
		private void computePin() {
			try {
				myStore = SecurityUtils.getInitializedKeyStore(pin);
			}catch (Exception e){
				logException(e);
			}
			
		} // computePin
		
		private void computeSign() {
			try {
				byte [] signData = SecurityUtils.sign(textToSign.getBytes(), privateKey);
				sign = signData.toString(); 
				verified = SecurityUtils.verify(textToSign.getBytes(), certificate, signData) ? "VERIFIED":"UNVERIFIED";
			}catch (Exception e){
				logException(e);
			}
			
		} // computePin
		
		@SuppressWarnings("deprecation")
		public void paint( Graphics g ) {
			try {
	
				if(myStore != null && sign == null){
					Enumeration<String> aliases = myStore.aliases();
					int numCertificates = 0;
					aliasesMap = new HashMap<Integer, String>();
					while (aliases.hasMoreElements()){
						String selectedAlias= aliases.nextElement();
						aliasesMap.put(new Integer(numCertificates), selectedAlias);
						
						// Output results
						outText.appendText("alias[" + (numCertificates) + "] --> " +selectedAlias + "\n");
						
						numCertificates++;
					}
				}else if(sign != null){
					outText.appendText("*************************************** " +
							"BEGIN SIGN (" + verified + ") from '" + textToSign + "' ***************************************\n");
					outText.appendText(sign +"\n");
					outText.appendText("*************************************** " +
							"END SIGN (" + verified + ") from '" + textToSign + "' ***************************************\n");
				}
			} catch (Exception e) {
				logException(e);
			}
			
			if(errors.size()>0){
				outText.appendText("*************************************** " +
						"Errors occurs ***************************************\n");
				for(String error: errors){
					outText.appendText(error + "\n");
				}
				outText.appendText("*************************************** " +
						"EoF Errors ***************************************\n");
				errors.clear();
			}
		} // paint
		
		private void processPin() { // reads float values from text fields
			pin = pinText.getText();
		} // processPin
		
		private void processSign() { // reads float values from text fields
			try {
				processPin();
				textToSign = textText.getText();
				String alias = aliasesMap.get(Integer.decode(certText.getText()));
				privateKey = (PrivateKey) myStore.getKey(alias, pin.toCharArray());
				certificate = (X509Certificate) myStore.getCertificate(alias);
			} catch (Exception e) {
				logException(e);
			}
		} // processSign
		
		public void actionPerformed(ActionEvent e) {
		
			if (e.getSource() == goButton) {
				processPin();
				computePin();
				repaint();
			}else if (e.getSource() == signButton) {
				processSign();
				computeSign();
				repaint();
			}
		} // actionPerformed
		
		private void makeGui() {
			Panel allPanel;
			
			// applet layout
				setLayout(new BorderLayout());
				
			// panel to hold all input elements
			allPanel = new Panel();
			allPanel.setLayout(new GridLayout(6,1));
			
			// pin
				pinText = new TextField(10);
				makeWidget("PIN", pinText, allPanel);
				
			// cert
				certText = new TextField(10);
				makeWidget("ALIAS", certText, allPanel);
				
			// text
				textText = new TextField(10);
				makeWidget("Text to sign", textText, allPanel);
				

			Panel bP = new Panel();
			// go button
			goButton = new Button("Get certificates");
			bP.add(goButton);
			goButton.addActionListener(this);
			// sign button
			signButton = new Button("Sign");
			bP.add(signButton);
			signButton.addActionListener(this);
			allPanel.add(bP);
			
			// add all panel to applet
			
			add("West", allPanel);
			
			// Output area
			outText = new TextArea("Output\n\n", 20, 40, TextArea.SCROLLBARS_BOTH);
			outText.setBackground(new Color(180, 180, 180));
			add("Center", outText);
			
		} // makeGui
		
		private void makeWidget(String lstring, TextField text, Panel all) {
			Label l;
			Panel p = new Panel();
			
			l = new Label(lstring);
			//text = new TextField(10);
			p.setLayout(new FlowLayout(FlowLayout.RIGHT));
			p.add(l);
			p.add(text);
			all.add(p);
		
		} // makeWigdet

}
