/* 
 * OpenSCTestBase.java Copyright (C) 2012 This file is part of OpenSC project
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
package org.opensc.testing;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * Utilities to manage security from java for OpenSC
 * 
 * @author adiaz
 *
 */
public class SecurityUtils {

	/* TODO: read from properties */
	public static String SLOT = "1"; //TODO parametrize
	public static final String WINDOWS = "win";
	public static final String OS_X = "mac";
	public static final String LINUX = "lin";
	public static final Map<String, String> CONFIG_LIB;
	static{
		CONFIG_LIB = new HashMap<String, String>();
		CONFIG_LIB.put(WINDOWS, "C:\\WINDOWS\\system32\\opensc-pkcs11.dll");
		CONFIG_LIB.put(OS_X, "/usr/local/lib/opensc-pkcs11.so");
		CONFIG_LIB.put(LINUX, "/usr/lib/opensc-pkcs11.so");
	}
	public static String getLibraryLocation(){
		String pkcs11LibName = "";
		String osName = System.getProperty(OS_NAME_PROPERTY).toLowerCase();
		if(osName.startsWith(WINDOWS)) pkcs11LibName = CONFIG_LIB.get(WINDOWS);
		else if(osName.startsWith(LINUX)) pkcs11LibName = CONFIG_LIB.get(LINUX);
		else if(osName.startsWith(OS_X)) pkcs11LibName = CONFIG_LIB.get(OS_X);
		return pkcs11LibName;
	}
    private static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";
	

	public static final String OS_NAME_PROPERTY = "os.name";
	public static final String name = "OpenSC PKCS#11";
	public static final String certAlias="CertFirmaDigital"; 
	
	public static Provider pkcs11Provider;
	
	static{
		try{
			/* PKCS#11 Security Provider */
			String pkcs11LibName = getLibraryLocation();
			
			//Define SunPKCS#11 parameters
            String PKCS11Library = pkcs11LibName;
            String ext = "attributes(*,*,*)=\n{\nCKA_TOKEN=true\nCKA_LOCAL=true\n}";

            //Compose configuration file
            String configString =  "name = " + name.replace(' ', '_') + "\n" +
                            "library = " + PKCS11Library +
                            "\n slot = "+  SLOT + " " + 
                            "\n attributes = compatibility \n" +
                            ext;
            //System.out.println(configString);
            byte[] configBytes = configString.getBytes();
            ByteArrayInputStream configStream = new ByteArrayInputStream(configBytes);

            //Load SunPKCS#11 provider
            pkcs11Provider = new sun.security.pkcs11.SunPKCS11(configStream);
            Security.addProvider(pkcs11Provider);
		}catch (Exception e){
			e.printStackTrace();
		}
	}

	/**
	 * Obtain OpenSC PKCS#11 keystore initialized with <code>pin</code>
	 * 
	 * @param pin
	 * @return keystore initialized
	 * @throws Exception
	 */
	public static KeyStore getInitializedKeyStore(String pin) throws Exception {
		KeyStore myKeyStore = getKeyStore();
        char[] pinData = pin.toCharArray();
		
        myKeyStore.load(null, pinData);
        return myKeyStore;
	}

	/**
	 * Obtain OpenSC PKCS#11 keystore without init 
	 * 
	 * @return keystore for be initialized with PIN 
	 * 
	 * @throws Exception
	 */
	public static KeyStore getKeyStore() throws Exception {
		
        return KeyStore.getInstance("PKCS11", pkcs11Provider);
	}
	
	/**
	 * Sign and verify an array of bytes
	 * 
	 * @param dataToSign
	 * @param alias to use in sign
	 * @param pin
	 * @param keyStore
	 * 
	 * @return <code>true</code> if the sign verification its true or <code>false</code> otherwise
	 * 
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 */
	public static boolean simpleSign(byte [] dataToSign, String alias, char[] pin, KeyStore keyStore) 
			throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException{
		  //Initialize private key object
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, pin);
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        byte[] dataSignature = sign(dataToSign, privateKey);
        return verify(dataToSign, certificate, dataSignature);
	}
	
	/**
	 * Sign bytes with  <code>privateKey</code>
	 * 
	 * @param dataToSign
	 * @param privateKey
	 * 
	 * @return <code>sign</code>
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public static byte[] sign(byte [] dataToSign, PrivateKey privateKey) 
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		Signature sig = Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME);
        sig.initSign(privateKey);
        sig.update(dataToSign);
        return sig.sign();
	}
	
	/**
	 * 
	 * @param dataToSign
	 * @param certificate
	 * @param dataSignature
	 * @return
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	public static boolean verify(byte [] dataToSign, X509Certificate certificate, byte[] dataSignature) 
			throws SignatureException, InvalidKeyException, NoSuchAlgorithmException{
		Signature verificacion = Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME);
        verificacion.initVerify(certificate);
        verificacion.update(dataToSign);
        return verificacion.verify(dataSignature);
	}

	/**
	 * Remove the security provider
	 */
	@Override
	protected void finalize() throws Throwable {
		Security.removeProvider(pkcs11Provider.getName());
		super.finalize();
	}
	
	
	
}
